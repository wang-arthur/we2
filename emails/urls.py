from django.conf.urls import patterns, url

from emails import views

urlpatterns = patterns('',
	
	url(r'^$', views.index, name='index'),
	url(r'^theme/(?P<theme>q?[a-zA-Z]{3,25})?/?$', views.themepage, name='themepage'),
	url(r'^participant/(?P<username>q?[a-zA-Z0-9_-]{3,20})?/?$', views.useremails, name='useremails'),
	url(r'^add/?$', views.add, name='add'),
	url(r'^signup/?$', views.signup, name='signup'),
	url(r'^login/?$', views.userlogin, name='login'),
	url(r'^logout/?$', views.userlogout, name='logout'),
	
	#add theme page -- superuser only
	url(r'^newtheme/?$', views.addtheme, name='addtheme'),
	url(r'^about/?$', views.about, name='about'),
)


