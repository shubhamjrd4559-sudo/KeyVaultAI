from django.urls import path

from .views import (
    CredentialCopyView,
    CredentialDetailView,
    CredentialListCreateView,
    CredentialRevealView,
)

urlpatterns = [
    path("credentials/", CredentialListCreateView.as_view(), name="credential-list-create"),
    path("credentials/<str:credential_id>/", CredentialDetailView.as_view(), name="credential-detail"),
    path("credentials/<str:credential_id>/reveal/", CredentialRevealView.as_view(), name="credential-reveal"),
    path("credentials/<str:credential_id>/copy/", CredentialCopyView.as_view(), name="credential-copy"),
]
