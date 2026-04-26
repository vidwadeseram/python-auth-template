Initial work was blocked by editing the wrong python-auth-template path; the correct repo is under templates/python-auth-template.
MailHog is not host-exposed in docker-compose, so token verification used docker-compose exec against the app container to query MailHog's API.
