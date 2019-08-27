cd ~/webapps/django/mycareerstack/ || exit
git show --pretty="" --name-only  "$2" | grep ".py" | xargs flake8 > "$2"1.txt
#git show --pretty="" --name-only  "$2" | grep ".py" | xargs pylint > "$2"2.txt
linty_fresh "$2"1.txt --pr_url "https://bitbucket.org/mycareerstack/django_mycareerstack/pull-requests/$1" --commit "$2" --linter "pylint" --reporter "bitbucket"
rm "$2"1.txt
#rm "$2"2.txt