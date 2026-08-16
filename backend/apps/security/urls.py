from django.urls import path
from .views import SecurityCredentialsView, SecuritySummaryView

urlpatterns = [
    path("summary/",     SecuritySummaryView.as_view(),     name="security-summary"),
    path("credentials/", SecurityCredentialsView.as_view(), name="security-credentials"),
]
