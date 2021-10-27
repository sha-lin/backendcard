from django.urls import path
from . import views


urlpatterns = [
    path('', views.SubjectListAPIView.as_view(), name="subjects"),
    path('<int:id>', views.SubjectDetailAPIView.as_view(), name="subjects"),
]