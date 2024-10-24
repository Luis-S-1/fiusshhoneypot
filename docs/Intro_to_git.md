This file was put together mostly by following the youtube video by Kevin Stratvert:
https://www.youtube.com/watch?v=tRZGeaHPoaw

initital git configuration in WSL (or a linux terminal of your choice):

for help:
git [command] -h
e.g. git config -h
git help config


git config --global user.name "Luis S"
git config --global user.email xxxxxxxx@fiu.edu

set default branch name to "main":
git config --global init.defaultBranch <name>

Creating your first repository:
cd into directory that you wish to track in git and do:
git init

check status:
git status

add one file for tracking:

git add index.htm

try untracking it:
git rm --cached index.htm

Ignoring files, folders, extensions:
Create new file with extension .gitignore:


now track all the files in this directory:

could use
git add --all OR git add -A
but instead let's use
git add .

commit the repository, to take a snapshot of all these files that we can come back to 
in the future:

git commit -m "first commit - committing all files to the repository"

observe that 'git status' now says "nothing to commit"

Make a change in a file:
modify chicken line to say "chickens that are free range" instead of what is there currently.

git status now reports that index.html has been modified.

to see the difference:

git diff

satisfied with the change, now do

git add index.html

this puts the file in 'staging' mode, and it stays there until you're ready to commit it.

[3 stages in GIT:
Working files
Staging
Commit
]

let's say you're not satisfied with the file now, so you do 

git restore --staged index.htm

this puts the file back in "working files" stage

we can also bypass staging altogether and just commit:

git commit -a -m "updated text to free range"

now delete the file 'secret recipe.htm'
observe the change in git status

Let's restore this file!
git restore "secret recipe.htm"

now rename a file:
git mv "KCC Logo.png" "Primary Logo.png"

commit the change with an explanation:
git commit -m "changed the file name of an image"


check history of changes to the repository:

git log

git log --oneline   [for abbreviated version]

git commit -m "Changed file name to Primary Logo.png" --amend

git log -p to see a diff in each commit


REVERT BACK TO A PREVIOUS COMMIT:

git reset [hashtag seen in git log --oneline]

e.g. 'git reset 67a9bdd'

Modify the order that the commits appear in with rebase
e.g. git rebase -i --root


BRANCHING:

e.g. git branch FixTemp

now do 'git branch'

you should see you have 2 branches now. (main and FixTemp, active one has an *)

now switch to the new branch:

git switch FixTemp

Change the secret recipe htm file to say 375F instead of 500.


do

git commit -a -m "updated temp for baking instructions"

you can switch back to main (or master) branch and you'll see it restores the files to the proper state.


Merge FixTemp branch into main:

git merge -m "Merge fixtemp back to main" FixTemp


Now delete the FixTemp branch:

git branch -d FixTemp


What if you created a branch and you want to merge it back in but main has since changed?
This generates a merge conflict
(see below what can be done)


create and switch to a new branch:
git switch -c UpdateText

edit the index.htm file to say 'best' instead of 'finest'

commit the change:
git commit -a -m "update index text"

Now make a change in main:
git switch main

edit index.htm to say "most amazing' instead of 'finest'

commit this in main branch:

git commit -a -m "update index text"

try merging changes from UpdateText back to main :

git merge UpdateText

merge CONFLICT

So delete these lines from index.htm to keep the UpdateText branch version:
<<<<<<< HEAD
<p>Every cookie made at the Kevin Cookie company is crafted with only the most amazing ingredients. Butter from grass fed cows. Unbleached flour with the best flavor and textures. Organic sugar only from India. Eggs from chickens that are free range. Even our water is special. It comes from the Cascade Mountain springs that we hike up to retrieve. Baking is our passion and we take it very seriously.</p>
=======

and delete
>>>>>>> UpdateText


Try to commit again:

git commit -a -m "update text on index"

it will work, and that's one way to resolve merge conflicts.












