from rest_framework.response import Response
from rest_framework.views import APIView

from .services.health import dependency_health


class HealthView(APIView):
    authentication_classes = []
    permission_classes = []

    def get(self, request):
        services = dependency_health()
        healthy = all(status == "ok" for status in services.values())
        return Response({"status": "ok" if healthy else "degraded", "services": services}, status=200 if healthy else 503)
