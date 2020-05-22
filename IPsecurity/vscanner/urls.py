from django.urls import path
from . import views


urlpatterns = [
        path('', views.button),
        path('output',views.output,name='script')
]
