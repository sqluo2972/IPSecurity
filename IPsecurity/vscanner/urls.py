from django.urls import path
from . import views


urlpatterns = [
        path('', views.button),
        path('output',views.output,name='script'),
        path('detail/<str:CVE>/',views.detail,name='cve_detail')
]
