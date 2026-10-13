from django.urls import path

from .views import (
    CredentialCopyView,
    CredentialDetailView,
    CredentialListCreateView,
    CredentialPermanentDeleteView,
    CredentialRestoreView,
    CredentialRevealView,
    CredentialSoftDeleteView,
    RecentlyDeletedListView,
)

urlpatterns = [
    path("credentials/", CredentialListCreateView.as_view(), name="credential-list-create"),
    path("credentials/<str:credential_id>/", CredentialDetailView.as_view(), name="credential-detail"),
    path("credentials/<str:credential_id>/reveal/", CredentialRevealView.as_view(), name="credential-reveal"),
    path("credentials/<str:credential_id>/copy/", CredentialCopyView.as_view(), name="credential-copy"),
    path("credentials/<str:credential_id>/soft-delete/", CredentialSoftDeleteView.as_view(), name="credential-soft-delete"),
    path("credentials/<str:credential_id>/restore/", CredentialRestoreView.as_view(), name="credential-restore"),
    path("credentials/<str:credential_id>/permanent-delete/", CredentialPermanentDeleteView.as_view(), name="credential-permanent-delete"),
    path("recently-deleted/", RecentlyDeletedListView.as_view(), name="recently-deleted"),
]
