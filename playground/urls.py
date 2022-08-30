from django.urls import path
from . import views
from .views import *


urlpatterns = [
    path("", home_view),
    path("get/new/", get_new_cve),
    path("get/all/", get_all_cve),
    path("get/critical/", get_crit_cve),
    path("get/crit/pdf/", get_crit_pdf),
    path("get/new/pdf/", get_new_pdf),
    path("get/all/pdf/", get_all_pdf)
]
