from django.db import models
from django.contrib.auth.models import User
'''
class ThemeManager(models.Manager):
	def create_theme(self, title, description):
		newtheme = self.create(title=title, description=description)
		return newtheme
'''
class Theme(models.Model):
	#short title for URL
	title = models.CharField(max_length=25)
	# full description of theme
	description = models.CharField(max_length=250)
	created = models.DateTimeField("date created", auto_now_add=True)

	# for potential debugging
	count = models.IntegerField(default=0)
	def __unicode__(self):
		return self.title

'''
class EmailManager(models.Manager):
	def create_email(self, sender, recipientname, recipientemail, subject, body, time_sent):
		newemail = self.create(sender = sender, recipientname = recipientname, recipientemail = recipientemail, subject = subject, body = body, time_sent = time_sent)
		return newemail
'''
class Email(models.Model):
	theme = models.ForeignKey(Theme)

	# sender is the user
	sender = models.ForeignKey(User, related_name='sender_user')

	# name of recipient
	recipient = models.CharField(max_length=100)
	
	subject = models.CharField(max_length = 200, blank=True)
	body = models.TextField()
	time_sent = models.DateTimeField(blank = True, null = True)
	created = models.DateTimeField(auto_now_add=True)

	def __unicode__(self):
		return self.subject


