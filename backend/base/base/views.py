from django.shortcuts import render



# react 랜더링
def index(request) :
    return render(request, 'index.html')