#!/usr/bin/env sh

help()
{
  # Display Help
  echo "Generate a CSV from a SQLITE TLS ciphersuite database and query."
  echo
  echo "Use tls-scraper to generate the SQLite database."
  echo
  echo "Syntax: query.sh [-h|-v] SQL_DATABASE SQL_QUERY CSV_FILE"
  echo "Options:"
  echo "h     Print this Help."
  echo "V     Print software version and exit."
  echo
  echo "Example:"
  echo "$ tls-scraper export --format SQL --output ciphersuites.sqlite"
  echo "$ sh query.sh ciphersuites.sqlite all_ciphersuites.sql all_ciphersuites.csv"
  echo
}


while getopts "hv" option; do
  case $option in
    h) # display Help
     help
     exit;;
    v)
      echo "0.0.0"
      exit;;
  esac
done

shift $(($OPTIND - 1));
SQL_DATABASE=${1}
SQL_QUERY=${2}
CSV_FILE=${3}

sqlite3 -header -csv ${SQL_DATABASE} < ${SQL_QUERY} > ${CSV_FILE}
