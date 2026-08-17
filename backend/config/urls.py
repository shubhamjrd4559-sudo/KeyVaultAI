from django.urls import include, path

urlpatterns = [
    path("api/v1/", include("apps.common.urls")),
    path("api/v1/auth/", include("apps.users.urls")),
    path("api/v1/vault/", include("apps.vault.urls")),
    path("api/v1/security/", include("apps.security.urls")),
    path("api/v1/ml/", include("apps.ml_engine.urls")),
]
