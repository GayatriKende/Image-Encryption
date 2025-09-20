from django.db import models

class EncryptedFile(models.Model):
    original_filename = models.CharField(max_length=512)
    ciphertext = models.BinaryField()  # store encrypted data directly in DB
    sha256 = models.CharField(max_length=64)
    salt = models.CharField(max_length=64)          # hex
    nonce = models.CharField(max_length=48)         # hex (12-16 bytes)
    tag = models.CharField(max_length=64)           # hex (16 bytes)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.original_filename} ({self.id})"

from rest_framework import serializers

class UploadSerializer(serializers.Serializer):
    file = serializers.ImageField()

import os
import hashlib
import binascii
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def derive_key(master_key: bytes, salt: bytes, length: int = 32) -> bytes:
    """Derive a per-file key (AES-256) using HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=b"file-encryption",
        backend=default_backend()
    )
    return hkdf.derive(master_key)


def encrypt_bytes(plaintext: bytes, key: bytes) -> (bytes, bytes):
    """Encrypt bytes using AES-GCM. Returns (nonce, ciphertext_with_tag)."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ct


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

import os
import binascii
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from .serializers import UploadSerializer
from .utils import derive_key, encrypt_bytes, sha256_hex
from .models import EncryptedFile

class UploadEncryptedView(APIView):
    permission_classes = [permissions.AllowAny]  # change to IsAuthenticated in production

    def post(self, request, format=None):
        serializer = UploadSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        upload = serializer.validated_data['file']
        original_bytes = upload.read()
        original_name = upload.name

        # compute sha256
        sha = sha256_hex(original_bytes)

        # derive per-file key
        master_key_b64 = os.environ.get('MASTER_KEY')
        if not master_key_b64:
            return Response({'error': 'MASTER_KEY not configured on the server'}, status=500)

        master_key = binascii.a2b_base64(master_key_b64)
        salt = os.urandom(16)
        key = derive_key(master_key, salt)

        # encrypt
        nonce, ciphertext_and_tag = encrypt_bytes(original_bytes, key)

        # store in DB
        ef = EncryptedFile.objects.create(
            original_filename=original_name,
            ciphertext=ciphertext_and_tag,
            sha256=sha,
            salt=binascii.hexlify(salt).decode(),
            nonce=binascii.hexlify(nonce).decode(),
            tag=binascii.hexlify(ciphertext_and_tag[-16:]).decode()
        )

        return Response({
            'id': ef.id,
            'filename': ef.original_filename,
            'sha256': ef.sha256,
            'salt': ef.salt,
            'nonce': ef.nonce,
            'created_at': ef.created_at
        }, status=201)

from django.urls import path
from .views import UploadEncryptedView

urlpatterns = [
    path('upload/', UploadEncryptedView.as_view(), name='upload-encrypted'),
]

