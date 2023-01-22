# OchronaDanych
Projekt z ochrony danych - aplikacja flaskowa

By uruchomić mój program najpierw trzeba wpisać:
- docker compose build

Następnie po zbudowaniu, należy wpisać
- docker compose up

Krótki opis - Aplikacja pozwala na stworzenie konta, które sprawdza hasło pod względem długości oraz złożoności (entropia). Hasło jest hashowane i przechowywane w SQLite.
Przy logowaniu (lub nagminnym klikaniu przycisku "Register" i "Go back" przed logowaniem), aplikacja zostanie zablokowana na 5 minut by zapobiec próbom brute force. Dodatkowo informacje udzielane przy logowaniu są lakoniczne i zwięzłe, przez co nie dają dokładnej informacji czy błąd nastąpił z winy hasła czy loginu.
Po zalogowaniu mamy zdanie powitalne, krótką ściągę stylów, jakich możemy użyć w naszej notatce, opcję stworzenie udostępnionej notatki, pole tekstowe do wpisania  notatki, możliwość zahasłowania jej, a także (pod warunkiem że mamy jakiekolwiek notatki) wylistowane notatki (odpowiednio Nasze, Zahasłowane, Udostępnione do wszyskich).
Po stworzeniu notatek dostajemy ich podgląd niezależnie od tego jaki rodzaj notatki tworzymy.
Przy otwieraniu notatek naszych lub udostępnionych po prostu wyświetla się nam notatka, z kolei przy zahasłowanej strona przekierowuje nas do miejsca, gdzie mamy podać hasło, w przypadku podania poprawnego hasła - pokazuje nam jej zawartość.
Na samym końcu głównego menu mamy jeszcze przycisk log out pozwalający nam wylogować się z konta.
