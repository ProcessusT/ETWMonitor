::[Bat To Exe Converter]
::
::YAwzoRdxOk+EWAjk
::fBw5plQjdCyDJGyX8VAjFCtGQweHL3ivFYk45//14+WGpl4hX+ssa5/V3fmNIfRe40bre9su124Xj8IYBFZLaxysYg4numtR+zGEb8XL5Vm5Gxnat05pVTUj0DeG2XpsMYY5w5NbinLrqh2oz/Fe2HvwPg==
::YAwzuBVtJxjWCl3EqQJgSA==
::ZR4luwNxJguZRRnk
::Yhs/ulQjdF+5
::cxAkpRVqdFKZSDk=
::cBs/ulQjdF+5
::ZR41oxFsdFKZSDk=
::eBoioBt6dFKZSDk=
::cRo6pxp7LAbNWATEpCI=
::egkzugNsPRvcWATEpCI=
::dAsiuh18IRvcCxnZtBJQ
::cRYluBh/LU+EWAnk
::YxY4rhs+aU+JeA==
::cxY6rQJ7JhzQF1fEqQJQ
::ZQ05rAF9IBncCkqN+0xwdVs0
::ZQ05rAF9IAHYFVzEqQJQ
::eg0/rx1wNQPfEVWB+kM9LVsJDGQ=
::fBEirQZwNQPfEVWB+kM9LVsJDGQ=
::cRolqwZ3JBvQF1fEqQJQ
::dhA7uBVwLU+EWDk=
::YQ03rBFzNR3SWATElA==
::dhAmsQZ3MwfNWATElA==
::ZQ0/vhVqMQ3MEVWAtB9wSA==
::Zg8zqx1/OA3MEVWAtB9wSA==
::dhA7pRFwIByZRRnk
::Zh4grVQjdCyDJGyX8VAjFCtGQweHL3ivFYk45+vu4u+Jtl4hc+srUJrZ5pG6F80c5EzweoQR805ttcQCBQ9XbFKKaQo6vVJnglO2MtWKugzkdk+M8nQjHndignHvhSU9b8BXitEG2i6t6Ezzk+sVyX2f
::YB416Ek+ZW8=
::
::
::978f952a14a936cc963da21a135fa983
@echo off
echo Enter ETW Monitor server IP address : 
set /p server_ip=""
cls
echo Enter ETW Monitor server token : 
set /p server_token=""
cls

mkdir "C:\Program Files\Processus Thief"
mkdir "C:\Program Files\Processus Thief\ETWMonitor Agent"
echo "SERVER_IP=%server_ip%;" > "C:\Program Files\Processus Thief\ETWMonitor Agent\settings.conf"
echo "TOKEN==%server_token%;" >> "C:\Program Files\Processus Thief\ETWMonitor Agent\settings.conf"

echo Settings file has been created.
pause 