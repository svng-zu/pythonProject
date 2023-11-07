import pickle
from .models import Video  # yourapp은 애플리케이션 이름

def load_data_from_pkl(file_path):
    with open(file_path, 'rb') as file:
        data = pickle.load(file)
    for item in data:
        Video.objects.create(
            subsr=item['subsr'],
            asset_nm=item['asset_nm'],
            ct_cl=item['ct_cl'],
            genre_of_ct_cl=item['genre_of_ct_cl'],
            use_tms=item['use_tms'],
            strt_dt=item['strt_dt'],
            vod분류=item['vod분류'],
            day=item['day'],
            hour=item['hour']
        )
load_data_from_pkl("C:/Users/USER/Desktop/LG헬로비전/VOD 추천 서비스 개발/vod.pkl")
# 경로는 aws 에 올리게 된다면 해당 aws에 맞게 적용