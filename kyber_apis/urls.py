from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns

from . views import (
    GenerateKeysView,
    EncryptDataView,
    DecryptDataView
)

app_name = "kyber"

urlpatterns = [
    path('generate_keys/', GenerateKeysView.as_view(), name='generate_keys'),
    path('encrypt_data/', EncryptDataView.as_view(), name='encrypt_data'),
    path('decrypt_data/', DecryptDataView.as_view(), name='decrypt_data')
]

urlpatterns = format_suffix_patterns(urlpatterns)