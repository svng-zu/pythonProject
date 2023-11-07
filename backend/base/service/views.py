from django.shortcuts import render, get_object_or_404
from rest_framework.views import APIView
from .serializers import *
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework import status
from rest_framework.response import Response

import jwt
from django.contrib.auth import authenticate
from base.settings import SECRET_KEY
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import check_password
import pickle
from django.http import HttpResponse
from django.shortcuts import render
from .forms import PickleUploadForm  # PickleUploadForm은 앞서 정의한 폼(Form) 클래스
from .models import Video  # 데이터를 저장할 모델을 import
from django.http import JsonResponse
from .rec import similar_users, recommend_vod


def upload_pickle(request):
    if request.method == 'POST':
        form = PickleUploadForm(request.POST, request.FILES)
        if form.is_valid():
            pickle_file = form.cleaned_data['pickle_file']

            # Pickle 파일 처리
            try:
                with open(pickle_file, 'rb') as file:
                    data = pickle.load(file)

                    # 데이터베이스에 저장
                    for item in data:
                        video = Video(
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
                        video.save()

                return HttpResponse('Pickle data has been successfully imported to the database.')
            except Exception as e:
                return HttpResponse(f'Error: {str(e)}', status=500)
    else:
        form = PickleUploadForm()
    return render(request, 'upload_pickle.html', {'form': form})
#     def post(self, request):
#         serializer = UserSerializer(data = request.data)
#         if serializer.is_valid():
#             user = serializer.save()

#             #jwt 토큰 접근
#             token = TokenObtainPairSerializer.get_token(user)
#             refresh_token = str(token)
#             access_token = str(token.access_token)
#             res = Response(
#                 {
#                     "user": serializer.data,
#                     "message": "register successs",
#                     "token": {
#                         "access": access_token,
#                         "refresh": refresh_token,
#                     },
#                 },
#                 status=status.HTTP_200_OK,
#             )

#             #jwt token -> cookie 저장
#             res.set_cookie("access", access_token, httponly= True)
#             res.set_cookie("refresh", refresh_token, httponly= True)

#             return res
#         return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)

# class AuthAPIView(APIView):
#     #user 정보 확인
#     def get(self, request):
#         try:
#             #access token을 decode해서 유저 id 추출 -> 유저 식별
#             access = request.COOKIES['access']
#             payload = jwt.decode(access, SECRET_KEY, algorithms=['HS256'])
#             pk = payload.get('user_id')
#             user = get_object_or_404(User, pk = pk)
#             serializer = UserSerializer(instance=user)
#             return Response(serializer.data, status=status.HTTP_200_OK)
        
#         except(jwt.exceptions.ExpiredSignatureError):
#             #token 만료 시 토큰 갱신
#             data = {'refresh': request.COOKIES.get('refresh', None)}
#             serializer = TokenRefreshSerializer(data = data)
#             if serializer.is_valid(raise_exception=True):
#                 access = serializer.data.get('access', None)
#                 refresh = serializer.data.get('refresh', None)
#                 payload = jwt.decode(access, SECRET_KEY, algorithms=['HS256'])
#                 pk = payload.get('user_id')
#                 serializer = UserSerializer(instance=user)
#                 res = Response(serializer.data, status=status.HTTP_200_OK)
#                 res.set_cookie('access', access)
#                 res.set_cookie('refresh', refresh)
#                 return res
#             return jwt.exceptions.InvalidTokenError

#         except(jwt.exceptions.InvalidTokenError):
#             #사용 불가 토큰의 경우
#             return Response(status=status.HTTP_400_BAD_REQUEST)

#     #login
#     def post(self, request):
#         #user 인증
#         user = authenticate(
#             email = request.data.get('email'),
#             password = request.data.get("password")
#         )
#         #이미 있는 유저의 경우
#         if user is not None:
#             serializer = UserSerializer(user)
#             #jwt token 접근
#             token = TokenObtainPairSerializer.get_token(user)
#             refresh_token = str(token)
#             access_token = str(token.access_token)
#             res = Response(
#                 {
#                     "user": serializer.data,
#                     "message": "login success",
#                     "token": {
#                         "access": access_token,
#                         "refresh": refresh_token,
#                     },
#                 },
#                 status=status.HTTP_200_OK,
#             )
#             #jwt token -> cookie 저장
#             res.set_cookie('access', access_token, httponly=True)
#             res.set_cookie('refresh', refresh_token, httponly=True)
#             return res
#         else:
#             return Response(status=status.HTTP_400_BAD_REQUEST)
        
#     #log out
#     def delete(self, request):
#         #cookie에 저장된 token 삭제 -> logout 처리
#         response = Response({
#             "message": "Log out success"
#         },
#         status= status.HTTP_202_ACCEPTED
#         )
#         response.delete_cookie('access')
#         response.delete_cookie('refresh')
#         return response






#회원 가입
class SignupAPIView(APIView):
    def post(self, request):
        serializer = SingupSerializer(data = request.data)
        if serializer.is_valid():
            user = serializer.save()
            #jwt token 접근
            token = TokenObtainPairSerializer.get_token(user)
            refresh_token = str(token)
            access_token = str(token.access_token)
            res = Response(
                {
                    "user": serializer.data,
                    "message": "register successs",
                    "token": {
                        "access": access_token,
                        "refresh": refresh_token,
                    },
                },
                status=status.HTTP_200_OK,
            )
            #쿠키에 넣어주기...아직 어떤식으로 해야될지 모르겠는데 이렇게 설정만 우선 해주었다. 
            res.set_cookie("access", access_token, httponly=True)
            res.set_cookie("refresh", refresh_token, httponly=True)
            return res
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
#log in
class LoginView(APIView):
    # user 정보 확인
    def get(self, request):
        try:
            #access token을 decode해서 유저 id 추출 -> 유저 식별
            access = request.COOKIES['access']
            payload = jwt.decode(access, SECRET_KEY, algorithms=['HS256'])
            pk = payload.get('user_id')
            user = get_object_or_404(User, pk = pk)
            serializer = UserSerializer(instance=user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except(jwt.exceptions.ExpiredSignatureError):
            #token 만료 시 토큰 갱신
            data = {'refresh': request.COOKIES.get('refresh', None)}
            serializer = TokenRefreshSerializer(data = data)
            if serializer.is_valid(raise_exception=True):
                access = serializer.data.get('access', None)
                refresh = serializer.data.get('refresh', None)
                payload = jwt.decode(access, SECRET_KEY, algorithms=['HS256'])
                pk = payload.get('user_id')
                serializer = UserSerializer(instance=user)
                res = Response(serializer.data, status=status.HTTP_200_OK)
                res.set_cookie('access', access)
                res.set_cookie('refresh', refresh)
                return res
            return jwt.exceptions.InvalidTokenError

        except(jwt.exceptions.InvalidTokenError):
            #사용 불가 토큰의 경우
            return Response(status=status.HTTP_400_BAD_REQUEST)


    #log in
    def post(self, request):

        # user = authenticate(
        #     email = request.data.get('email'),
        #     password = request.data.get('password')
        # )
        email = request.data['email']
        pw = request.data['password']

        user = User.objects.filter(email = email).first()

        #user 존재 X
        if user is None:
            return Response(
                {"message": "Email Not exists."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        #pw wrong
        if not check_password(pw, user.password):
            return Response(
                {"message": "Wrong Password"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if user is not None:
            serializer = UserSerializer(user)
            token = TokenObtainPairSerializer.get_token(user) #refresh token 생성
            refresh_token = str(token) #token 문자열화
            access_token = str(token.access_token)

            user.is_active = True
            user.save()

            res = Response(
                {
                    "user": serializer.data,
                    "message": "login success",
                    "token": {
                        "access": access_token,
                        "refresh": refresh_token,
                    },
                },
                status=status.HTTP_200_OK,
            )

            res.set_cookie("access",access_token, httponly= True) #post method로 login 했을때 생성된 token을 쿠키에 담아 전송
            res.set_cookie("refresh", refresh_token, httponly=True)
            return res
        else:
            return Response(
                {"message":"login failed"},
                 status=status.HTTP_400_BAD_REQUEST)
    
    #logout
    def delete(self, request):
        update_user = User.objects.get(email = request.data['email'])
        update_user.is_active = False
        update_user.save()

        #cookie에 저장된 token 삭제 -> logout 처리
        res = Response({
            "message":"Log out success"
        }, status=status.HTTP_202_ACCEPTED)
        res.delete_cookie('accesss')
        res.delete_cookie('refresh')
        return res
        
    
# class LogoutView(APIView):
#     def post(self, request):
#         # serializer = UserSerializer(user)
#         refresh_token = request.data['refresh']
#         token = RefreshToken(refresh_token)
#         token.blacklist()
#         res = Response(
#             {"message": "logout success"}, status=status.HTTP_200_OK
#         )
#         res.delete_cookie('jwt')
#         return res
#         #redirect('')
#         #return render(request, '#.html')

def get_similar_users(request):
    if request.method == 'GET':
        user_id = request.GET.get('user_id', None)  # GET 요청에서 user_id를 가져옵니다.

        if user_id:
            similar_user_indices = similar_users(user_id)  # 수정한 함수 호출
            return render(request, 'service/similar.html', {'similar_user_indices': similar_user_indices})
        else:
            return JsonResponse({'error': 'user_id parameter is missing'})
    else:
        return JsonResponse({'error': 'Only GET requests are allowed'})

def get_recommendations(request):
    if request.method == 'GET':
        user_id = request.GET.get('user_id', None)  # GET 요청에서 user_id를 가져옵니다.

        if user_id:
            # 1. similar_users 함수를 사용하여 유사한 사용자 가져오기
            similar_user_indices = similar_users(user_id)

            if similar_user_indices:
                # 2. recommend_vod 함수를 사용하여 추천 VOD 가져오기
                recommended_vod = recommend_vod(user_id, similar_user_indices)

                if not recommended_vod.empty:
                    # 추천된 VOD가 있는 경우 응답으로 반환
                    return render(request, 'serivce/recommendations.html', {'recommended_vod': recommended_vod.to_dict(orient='records')})
                else:
                    return JsonResponse({'error': 'No recommended VOD found for the user'})
            else:
                return JsonResponse({'error': 'No similar users found for the user'})
        else:
            return JsonResponse({'error': 'user_id parameter is missing'})
    else:
        return JsonResponse({'error': 'Only GET requests are allowed'})