from django.urls import path
from . import views


urlpatterns = [
        path('', views.button,name='home'),
        path('output',views.output,name='script'),
        path('cve',views.cve,name='cve'),
        path('report',views.report,name='report'),
        path('detail/<str:CVE>/',views.detail,name='cve_detail')
]
