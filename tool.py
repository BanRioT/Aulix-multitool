import backend
from backend import *
import os

os.system("title Aulix")

while True:
    cmd = input(f"{Red} » {White}")

    if 'help' == cmd:
        print(f"""
{Yellow}- {Purple}[{Green}Basic commands{Purple}]{Dark_orange}:
{Blue}help {White}- Shows a list of available commands
{Blue}about {White}- Shows information about Aulix
{Blue}clear {White}- Clears the terminal

{Yellow}- {Purple}[{Green}Network commands{Purple}]{Dark_orange}:
{Blue}lookup {White}- Lookup information on a IP address
{Blue}port-scan {White}- Scans a host for open ports
{Blue}ping {White}- Sends packets to check the status of a host

{Yellow}- {Purple}[{Green}Osint commands{Purple}]{Dark_orange}:
{Blue}social-scrape {White}- Scrapes multiple social networks for information about the target
{Blue} {White}-
{Blue} {White}-
{Blue} {White}-
""")
