from django.db import models
from django.contrib.auth.models import AbstractBaseUser,BaseUserManager, PermissionsMixin

#helper class
class UserManager(BaseUserManager):
    def create_user(self, email, password, **kwargs):
        if not email:
            raise ValueError("Email is Required")
        if not password:
            raise ValueError("Password is required")
        
        user = self.model(
            email = email,
            **kwargs
        )
        user.set_password(password)
        user.save(using = self._db)
        return user

    def create_superuser(self, email = None, password = None, **kwargs):
        superuser = self.create_user(
            email = email,
            password = password,
        )

        superuser.is_staff = True
        superuser.is_superuser = True
        superuser.is_active = True

        superuser.save(using = self._db)
        return superuser

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(max_length=30, unique= True, null = False, blank = False)
    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default =False)
    joined_date = models.DateTimeField(auto_now_add=True)
    # updated_at = models.DateTimeField(auto_now= True)

    #helper class 사용
    objects = UserManager()

    #user username field는 email로 설정 -> email로 로그인
    USERNAME_FIELD = 'email'

    class Meta:
        db_table = 'user'