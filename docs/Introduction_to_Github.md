copy our repository to github from bash:

git remote add origin https://github.com/fiusshhoneypot/KevinCookieCompany.git [where origin is the name of the remote connection]

git branch -M main    [from github.com on how to "push an existing repository from the command line" ]

git push -u origin main


---------------------------------------------

Issues tab in Github can contain 'feature requests' or 'bugs'


---------------------------------------------------
To get stuff from Github into your local computer

you can do

git fetch [this will download all the history from the remote tracking branches]

then we could do 

git merge

to merge that in


OR instead of those 2 commands, we could do

git pull     [combines fetch and merge into one command]

----------------------------------------------------
check if a folder is being ignored by git  (handled by hidden .gitignore file in root project folder)

git check-ignore -v <foldername>/*



