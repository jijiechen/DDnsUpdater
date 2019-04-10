
# publish:
dotnet publish -o DnsUpdater -c Release --self-contained -r rhel-x64
tar -cvf dns-updator.tar ./DnsUpdater


# execute:
tar -xvf dns-updator.tar
cd DnsUpdater
echo '{ "runtimeOptions": { "configProperties": { "System.Globalization.Invariant": true } } }' > ./DnsUpdater.runtimeconfig.json 
./DnsUpdater $(dig +short myip.opendns.com @resolver1.opendns.com)