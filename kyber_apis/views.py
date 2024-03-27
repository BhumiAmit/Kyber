from django.shortcuts import render
from rest_framework import generics, status
from rest_framework.response import Response

from .serializers import (
    GenerateKeysSerializer,
    EncryptDataSerializer,
    DecryptDataSerializer
)

class GenerateKeysView(generics.ListAPIView):
    serializer_class = GenerateKeysSerializer

    # def create(self, request, *args, **kwargs):
    #     serializer = self.get_serializer(data=request.data)

    #     if serializer.is_valid():
    #         keys_data = serializer.save()
    #         return Response(keys_data, status=status.HTTP_201_CREATED)
    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def get_queryset(self):
        serializer = self.serializer_class()
        queryset = serializer.get()
        return queryset

    def get(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        return Response(queryset)
    
class EncryptDataView(generics.CreateAPIView):
    serializer_class = EncryptDataSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            response = serializer.save()
            return Response(response, status=status.HTTP_201_CREATED)
        return Response({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
    
class DecryptDataView(generics.CreateAPIView):
    serializer_class = DecryptDataSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            response = serializer.data
            return Response(response, status=status.HTTP_201_CREATED)
        return Response({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
