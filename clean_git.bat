@echo off
echo Очистка Git от ненужных файлов...

REM Удаляем файлы из индекса Git, но оставляем их в файловой системе
git rm -r --cached .
git add .
git status

echo.
echo Готово! Теперь выполните:
echo git commit -m "Remove ignored files"
echo git push
pause 