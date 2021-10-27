from django.db import models
from authentication.models import User


# Create your models here.


class Subject(models.Model):

    CATEGORY_OPTIONS = [
        ('HISTORY', 'HISTORY'),
        ('SCIENCE AND TECHNOLOGY', 'SCIENCE AND TECHNOLOGY'),
        ('HOMESCIENCE', 'HOMESCIENCE'),
    ]

    category = models.CharField(choices=CATEGORY_OPTIONS, max_length=255)
    description = models.TextField()
    owner = models.ForeignKey(to=User, on_delete=models.CASCADE)
    date = models.DateField(null=False, blank=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # class Meta:
    #     ordering: ['-updated_at']

    # def __str__(self):
    #     return str(self.owner)+'s subject'
