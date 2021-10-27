from rest_framework import serializers
from .models import Subject


class SubjectsSerializer(serializers.ModelSerializer):

    class Meta:
        model = Subject
        fields = ['id', 'date', 'description', 'category']