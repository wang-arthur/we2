from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.shortcuts import render, redirect, get_object_or_404, get_list_or_404
from django.http import HttpResponse
from django.core.cache import cache
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

from models import Email, Theme

import logging
import re
import datetime
'''

	clean up cache to avoid collisions!
	views:
	by participant
	by theme

	navbar contingent on login
'''
# CACHE FUNCTIONS
def userlist(update = False):
	key = 'userlist'
	users = cache.get(key)
	if users is None or update:
		logging.error("participant list DB Query")
		users = User.objects.all().order_by("first_name")
		users = list(users)
		cache.set(key, users)
	return users

def themelist(update=False):
	key = 'themelist'
	themes = cache.get(key)
	if themes is None or update:
		logging.error("theme list DB query")
		themes = Theme.objects.all().order_by("-created")
		themes = list(themes)
		cache.set(key, themes)
	return themes


def theme_by_title(title, update = False):
	key = '123'+title
	theme = cache.get(key)
	if theme is None or update:
		theme = get_object_or_404(Theme, title=title)
		cache.set(key, theme)
	return theme

def emails_by_theme(theme, update=False):
	key = '930'+str(theme)
	emails = cache.get(key)
	if emails is None or update:
		logging.error(str(theme) + "email DB query")
		emails = Email.objects.filter(theme=theme).order_by("-created")
		emails = list(emails)
		cache.set(key, emails)
	return emails

def emails_by_user(user, update=False, delete=False):
	key = '999'+str(user.pk)
	emails = cache.get(key)
	if delete:
		if emails:
			cache.delete(key)
		return
	if emails is None or update:
		emails = Email.objects.filter(sender=user).order_by("-created")
		emails = list(emails)
		cache.set(key, emails)
	return emails

def user_by_username(username, update=False, delete=False):
	key = '540' + username
	user = cache.get(key)
	if delete:
		if user:
			cache.delete(key)
		return
	if user is None or update:
		user = get_object_or_404(User, username=username)
		cache.set(key, user)
	return user
## END CACHE FUNCTIONS



def index(request):
	participants = userlist()
	themes = themelist()
	# lists participants
	return render(request, "emails/index.html", {'participants': participants, 'themes': themes})

def themepage(request, theme):
	participants = userlist()
	themes = themelist()
	theme = theme_by_title(theme)
	emails = emails_by_theme(theme)
	return render(request, "emails/theme.html", {'emails': emails, 'theme': theme, 'participants': participants, 'themes': themes})

def addtheme(request):
	def render_form(title="", description="", error=""):
		participants = userlist()
		themes = themelist()
		return render(request, "emails/addtheme.html", {'participants': participants, 'themes': themes, 'title': title, 'description': description, 'error': error})

	if request.method == "POST" and request.user.is_superuser:
		title = request.POST.get('title')
		description = request.POST.get('description')
		if not title or not description:
			error = "Please enter a title and a description"
			return render_form(title, description, error)
		else:
			if not title.isalpha():
				error = "Theme titles must be letters only with no spaces"
				return render_form(error=error)
			# create new theme and update caches
			theme = Theme()
			theme.title = title
			if Theme.objects.filter(title=title):
				error = "A theme with that title already exists."
				return render_form(error=error)
			theme.description = description
			theme.save()
			themelist(True)
			theme_by_title(title, True)
			return redirect('/')
	else:
		return render_form()

def add(request):
	def render_form(selected_theme="", recipient="", timesent="", subject="", body="", error=""):
		participants = userlist()
		themes = themelist()
		return render(request, "emails/add.html", {'themes': themes, 'participants': participants,
			                                       'selected_theme': selected_theme, 'recipient': recipient, 'timesent': timesent,
			                                       'subject': subject, 'body': body, 'error': error})
	if request.method == 'POST' and request.user.is_authenticated():
		selected_theme = request.POST.get('theme')
		recipient = request.POST.get('recipient')
		timesent = request.POST.get('timesent')
		subject = request.POST.get('subject')
		body = request.POST.get('body')
		if not selected_theme or not recipient or not body:
			error = "Please complete all required fields"
			return render_form(selected_theme, recipient, timesent, subject, body, error)

		email = Email()
		email.theme = theme_by_title(selected_theme)
		email.sender = request.user
		email.recipient = recipient
		if timesent:
			email.time_sent = datetime.datetime.strptime(timesent, '%Y-%m-%dT%H:%M')
		if not subject:
			subject = "(no subject)"
		email.subject = subject
		email.body = body
		email.save()

		# update caches
		emails_by_user(request.user, True)
		emails_by_theme(email.theme, True)
		# redirect
		return redirect("/participant")

	else:
		return render_form()

def useremails(request, username):
	def render_form(user = request.user, success="", error=""):
		participants = userlist()
		themes = themelist()
		emails = emails_by_user(user)
		return render(request, "emails/participant.html", {'emails': emails, 'user': user, 'themes': themes, 'participants': participants, 'success': success, 'error': error})
	# post cases include: delete email, edit email, and forward page to friend
	if request.method == "POST" and request.user.is_authenticated():
		if 'delete' in request.POST:
			emailid = request.POST.get('delete')
			email = get_object_or_404(Email, pk=int(emailid))
			theme = email.theme
			email.delete()
			#update caches for emails_by_theme, emails_by_user
			emails_by_user(request.user, True)
			emails_by_theme(theme, True)
			success = "Email deleted!"
			return render_form(success=success)
			#return redirect(request.path + "?deleted=True")
		elif 'edit' in request.POST:
			# get all submitted fields
			emailid = int(request.POST.get('edit'))
			email = get_object_or_404(Email, pk=emailid)
			oldtheme = email.theme
			newtheme  = theme_by_title(request.POST.get('edittheme%d' %emailid))
			time_sent = request.POST.get('edittimesent%d' %emailid)
			recipient = request.POST.get('editrecipient%d' %emailid)
			subject = request.POST.get('editsubject%d' %emailid)
			body = request.POST.get('editbody%d' %emailid)
			if not newtheme or not recipient or not body:
				error = "Emails must include themes, recipients, and body text"
				return render_form(error=error)
			# edit email and save changes
			email = get_object_or_404(Email, pk=emailid)
			email.theme = newtheme
			if time_sent:
				email.time_sent = datetime.datetime.strptime(time_sent, '%Y-%m-%dT%H:%M')
			email.recipient = recipient
			email.subject = subject
			email.body = body
			email.save()
			#update caches
			emails_by_user(request.user, True)
			emails_by_theme(oldtheme, True)
			if newtheme != oldtheme:
				emails_by_theme(newtheme, True)
			success = "Changes saved!"
			return render_form(success=success)
		
		#elif 'emailfriend' in request.POST:
	
	# get request
	else:
		if request.user.is_authenticated():
			if username == request.user.username:
				return redirect('/participant')
			if username:
				user = user_by_username(username)
			else:
				user=request.user
		else:
			if username is None:
				return redirect('/')
			user = user_by_username(username)
		return render_form(user=user)



USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
  return (EMAIL_RE.match(email) or email == "")

def error_check(username, password, verify=None, email=None, firstname=None):
	error = ""
	#signup specific error
	if verify is not None:
		try:
			if User.objects.get(username=username):
				error = "That username is already taken.  Please choose another."
				return error
		except:
			if password != verify:
				error = "Passwords don't match."
	if email is not None:
		if not valid_email(email):
			error = "Please enter a valid email address or leave the email field blank."
	if firstname is not None and not firstname:
		error = "Please enter your first name"
	# error: invalid username or password
	if not valid_username(username) or not valid_password(password):
		error = "Please enter a valid username and password."	
	return error

def settings(request):
	def render_form(error="", success=""):
		participants = userlist()
		themes = themelist()
		return render(request, "emails/settings.html", {'participants': participants, 'themes': themes, 'error': error, 'success': success})
	if request.method == 'POST' and request.user.is_authenticated():
		if 'changename' in request.POST:
			firstname = request.POST.get('firstname')
			lastname = request.POST.get('lastname')
			if not firstname:
				error = "Your first name cannot be blank."
				return render_form(error=error)
			user = request.user
			user.first_name = firstname
			user.last_name = lastname
			user.save()
			userlist(True)
			success = "You have changed your name to: %s %s" %(firstname, lastname)
			return render_form(success=success)
		if 'changeemail' in request.POST:
			email = request.POST.get('email')
			if email and not valid_email(email):
				error = "Please enter a valid email address or leave the field blank to clear your email address."
				return render_form(error=error)
			user = request.user
			user.email = email
			user.save()
			if email:
				success = "You have changed your email address to: %s." %email
			else:
				success = "You have cleared your email address."
			return render_form(success=success)
		if 'changepass' in request.POST:
			oldpassword = request.POST.get('oldpass')
			newpassword = request.POST.get('newpass')
			user = authenticate(username=request.user.username, password=oldpassword)
			if user is None:
				error = "The old password you entered is not valid.  Please try again."
				return render_form(error=error)
			elif not valid_password(newpassword):
				error = "Your new password must be between 3 and 20 characters long."
				return render_form(error=error)
			else:
				user.set_password(newpassword)
				user.save()
				success = "You have successfully changed your password."
				return render_form(success=success)
		if 'deleteaccount' in request.POST:
			user = authenticate(username=request.user.username, password=request.POST.get('deletepass'))
			if user is None:
				error = "The password you entered is not valid."
				return render_form(error=error)
			else:
				user.delete()
				userlist(True)
				#update all emails by theme
				for theme in themelist():
					emails_by_theme(theme, True)
				# user_by_username and emails_by_user should be updated for cache space
				user_by_username(user.username, delete=True)
				emails_by_user(user, delete=True)
				return redirect("/")
	else:
		participants = userlist()
		themes = themelist()
		return render_form()


def signup(request):
	def render_form(firstname="", lastname="", email="", username="", error="", next_url="/"):
		participants = userlist()
		themes = themelist()
		return render(request, "emails/signup.html", {'firstname': firstname, 'lastname': lastname, 'email': email, 
			'username': username, 'error': error, 'next_url': next_url, 'participants': participants, 'themes': themes})
	if (request.POST):
		firstname = request.POST.get('firstname')
		lastname = request.POST.get('lastname')
		email = request.POST.get('email')
		username = request.POST.get('username')
		password = request.POST.get('password')
		verify = request.POST.get('verify')
		next_url = request.POST.get('next_url')
		error = error_check(username, password, verify, email, firstname)
		if error:
			return render_form(firstname, lastname, email, username, error, next_url)
		#successful signup: save user, login, and redirect to welcome page
		else:
			user = User.objects.create_user(username=username, password=password)
			user.first_name=firstname
			user.last_name=lastname
			user.email=email
			user.save()
			user=authenticate(username=username, password=password)
			login(request, user)

			#update user-related caches
			user_by_username(username, True)
			userlist(True)
			return redirect(next_url)
	else:
		next_url = request.META.get('HTTP_REFERER')
		if not next_url or '/login' in next_url or '/signup' in next_url:
			next_url = "/"
		# redirect already logged-in users
		if request.user.is_authenticated():
			return redirect(next_url)
		return render_form(next_url=next_url)


def userlogin(request):
	def render_form(username="", error="", next_url="/"):
		participants = userlist()
		themes = themelist()
		return render(request, "emails/login.html", {'username': username, 'error': error, 'next_url': next_url, 
			'participants': participants, 'themes': themes})
	if (request.POST):
		username = request.POST.get('username')
		password = request.POST.get('password')
		next_url = request.POST.get('next_url')
		error = error_check(username, password)
		if error:
			return render_form(username, error, next_url)
		else:
			user = authenticate(username=username, password=password)
			if user is not None:
				login(request, user)
				return redirect(next_url)
			else:
				error = "Please enter a valid username and password."
				return render_form(username, error, next_url)
	else:
		next_url = request.META.get('HTTP_REFERER')
		if not next_url or '/login' in next_url or '/signup' in next_url:
			next_url = "/"
		# redirect already logged-in users
		if request.user.is_authenticated():
			return redirect(next_url)
		return render_form(next_url=next_url)

def userlogout(request):
	next_url = request.META.get('HTTP_REFERER')
	if not next_url:
		next_url = "/"
	logout(request)
	return redirect(next_url)
def about(request):
	participants = userlist()
	themes = themelist()
	return render(request, "emails/about.html", {'participants': participants, 'themes': themes})

