import operator
import pandas as pd
from django.http import HttpResponse
from django.shortcuts import render
from .forms import PickleUploadForm  # PickleUploadForm은 앞서 정의한 폼(Form) 클래스
from .models import Video 
from sklearn.metrics.pairwise import cosine_similarity
def similar_users(user_id=65443000, k=5):
    try:
        # MySQL 데이터베이스에서 필요한 데이터 가져오기
        video_data_query = Video.objects.values('subsr', 'asset_nm', 'use_tms', 'vod분류')
        video_data_df = pd.DataFrame.from_records(video_data_query)

        # vod 정보 데이터프레임 생성
        vod_info = video_data_df.groupby(['asset_nm', 'vod분류']).count()[['subsr']].reset_index().rename(columns={'subsr':'subsr_count'})
        vod_info['use_tms_sum'] = video_data_df.groupby(['asset_nm', 'vod분류']).sum()[['use_tms']].reset_index()['use_tms']
        vod_info = vod_info.reset_index().rename(columns={'index':'vod_id'})

        # user_log 정보 데이터프레임 생성
        user_log = video_data_df[['subsr', 'asset_nm', 'use_tms']].merge(vod_info[['vod_id', 'asset_nm']]).sort_values(by='subsr').drop('asset_nm', axis=1)

        # 피벗 테이블 만들기 (user별 vod를 시청한 시청시간에 대한 pivot table)
        score_matrix = user_log.pivot_table(index='subsr', columns='vod_id', values='use_tms')

        # 결측치 제거
        score_matrix = score_matrix.fillna(0)

        # 현재 user_id에 대한 데이터프레임 준비
        user = score_matrix[score_matrix.index == user_id]
        
        # 나머지 user들에 대한 정보
        other_user = score_matrix[score_matrix.index != user_id]
        
        # 대상 user와 나머지 user들과의 유사도 계산
        sim = cosine_similarity(user, other_user)[0].tolist()
        
        # 나먨지 user들에 대한 목록 생성
        other_users_list = other_user.index.tolist()
        
        # 인덱스/유사도로 이루어진 딕셔너리 생성
        user_sim = dict(zip(other_users_list, sim))
        
        # 딕셔너리 정렬
        user_sim_sorted = sorted(user_sim.items(), key=operator.itemgetter(1))
        
        # 가장 높은 유사도 k개 정렬
        top_users_sim = user_sim_sorted[:k]
        users = [i[0] for i in top_users_sim]
        return users
    except Video.DoesNotExist:
        # 해당 user_id를 가진 사용자가 없는 경우 예외 처리
        return []
    

# vod 추천하기
def recommend_vod(user_id, similar_user_indices, items=10):
    try:
        # MySQL 데이터베이스에서 필요한 데이터 가져오기
        user_data_query = Video.objects.filter(subsr=user_id).values('subsr', 'vod_id', 'use_tms')
        user_data_df = pd.DataFrame.from_records(user_data_query)

        # MySQL 데이터베이스에서 비슷한 사용자 데이터 가져오기
        similar_users_data_query = Video.objects.filter(subsr__in=similar_user_indices).values('subsr', 'vod_id', 'use_tms')
        similar_users_data_df = pd.DataFrame.from_records(similar_users_data_query)

        # 미시청 vod 목록 가져오기
        user_unseen_vod = user_data_df[user_data_df['use_tms'] == 0]['vod_id'].unique()

        # 비슷한 사용자 중에서 미시청 vod 추출
        similar_users_unseen_vod = similar_users_data_df[
            (similar_users_data_df['vod_id'].isin(user_unseen_vod)) &
            (similar_users_data_df['subsr'] != user_id)
        ]

        # 유사한 사용자 평균 계산
        similar_users_avg = similar_users_unseen_vod.groupby('vod_id')['use_tms'].mean().reset_index()
        similar_users_avg = similar_users_avg.rename(columns={'use_tms': 'average_use_tms'})

        # 사용자와 유사한 사용자 평균 병합
        recommended_vod = pd.merge(user_unseen_vod, similar_users_avg, on='vod_id', how='left')

        # 평균값을 기준으로 내림차순 정렬
        recommended_vod = recommended_vod.sort_values(by='average_use_tms', ascending=False)

        # 상위 n개 값 가져오기
        top_n_vod = recommended_vod.head(items)

        # vod 정보 데이터프레임에서 top_n값 찾기
        vod_information_query = Video.objects.filter(vod_id__in=top_n_vod['vod_id']).values('vod_id', 'asset_nm', 'vod분류', 'genre_of_ct_cl')
        vod_information_df = pd.DataFrame.from_records(vod_information_query)

        return vod_information_df
    except Video.DoesNotExist:
        # 해당 user_id를 가진 사용자가 없는 경우 예외 처리
        return pd.DataFrame()