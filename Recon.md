##METHODOLOGY

[i]subdomain enumeration
		gives bigger attack surface
		look for preprod/env subdomains
		Perform REcursive Bruteforcing
		FUZZ.host -> dev.host -> Fuzz.dev.host
		
-understand technologies in all domains
		cat subs.txt | httpx -silent -title -tech-detect -status-code -web-server 
		cat subs.txt | sed 's~https\?://~~' | sed 's/\/$//' | \ naabu -p 80,443,8080,8000,8443 -rate 10000 -silent | \ httpx -silent -title -tech-detect -status-code -web-server | tee alive.txt
		httpx -l subs.txt -path "swagger/index.html" -mc 200 -sc -cl -title
[i] finding open ports

	nmap -p- -sV -O  34.117.134.166 --script vuln*

[*] Tool 
	Bbot
		bbot -t oda.com -p subdomain-enum -o subdomains.txt   
		sed 's|^|https://|' subdomains.txt > https_subdomains.txt
		grep '\.oda\.com$' subdomains.txt > filtered_subD.txt
		(NOW WE HAVE ALL THE SUBDOMAINS INN THE filtered_subD.txt )
		
		
[i]VHOST identification (IN THE BBOT FOLDER)
		Collect IP of oraganization and try to bruteforce HOST: header with subdomains of sam oraganization
		while read sub; do host $sub | awk '/has address/ {print $4}'; done < subdomains.txt | sort -u > /root/Desktop/workspace/subd_ip.txt

		while read sub; do dig +short $sub; done < subdomains.txt | sort -u > /root/Desktop/workspace/subd_ip.txt        

NOW GO TO DESKTOP AND RUN THIS COMMAND TO FETCH MORE IPS 
		./ipres.sh oda.com 

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	        
[i]ASN Mapping
		-some IP's show Connection reset but if you send right HOST (subdoamin of same comapny) in header with info
		-for i in ${cat ips};do ffuf -w subs  -u https://$i -H "Host: Fuzz" -of csv -o $i.csv;done
		
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
[i]Dorking
		aterrisks are the wildcards you want to search for
		
		
		responsible disclosure r=h:eu
		site:*.in inurl:"responsible disclosure"
		site:*.io intitle:"vulnerability disclosure" inurl:"program"
		site:*.com.* intitle:"vulnerability disclosure" inurl:"program"  (intext:"2025" )
		inurl /bountyprogram after:2025
		site:*.ai "bug bounty" 2025
		site:*.ai intext:"bug bounty program" 2025
		site:*.ai "vulnerability disclosure" OR "security.txt" 2025
		site:*.ai "report a vulnerability" 2025
		site:*.ai intitle:"bug bounty" intext:2025

for ssrf	assetfinder --subs-only app.coderabbit.ai | waybackurls |grep "?url="

		for doamin dorking ->   site:*<dyson>*
					site:dyson>*
					site:*<dyson.*>*
					site:*<*dyson.*>*
					site:*.example.com (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)	
					site:domain[.]com inurl:= inurl:? inurl:&
					site:*.gov.* "error in your SQL"

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------



start with wildcards for subomain 

##waybackcurl and  virustotal
		https://web.archive.org/cdx/search/cdx?url=*.example.com/*&collapse=urlkey&output=text&fl=original

		https://www.virustotal.com/vtapi/v2/domain/report?apikey=413f56941af6e94c585694b70ff0c670f8aa9383d51553ab149a4019df3fd7c1&domain=example.com

		https://otx.alienvault.com/api/v1/indicators/hostname/domain.com/url_list?limit=500&page=1

		curl -G "https://web.archive.org/cdx/search/cdx" --data-urlencode "url=hjelp.oda.com/*" --data-urlencode "collapse=urlkey" --data-urlencode "output=text" --data-urlencode "fl=original" > out.txt

	


[i] api reverse engineering

		mitmproxy2swagger -i ./flows -o spec.yml -p <URL> -f flow
		mitmproxy2swagger -i ./flows -o spec.yml -p <URL> -f flow --examples

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Linkfinder (to find all links in the webpage)

		python3 linkfinder.py -i https://example.com -o cli




- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
## automated JS endpoint extraction  -> 

🔹 Step 1: Collect URLs from Wayback & Katana

		echo "https://example.com/" | waybackurls | anew urls.txt  
		httpx -l urls.txt -mc 200 -silent -rate-limit 1 -o filtered_urls.txt  

		cat urls.txt | katana -d 3 -jc | hakrawler | anew katana.txt  
		cat katana.txt urls.txt | unfurl format %p | anew paths.txt  

🔹 Step 2: JavaScript Recon (Automated Endpoint Extraction)

		katana -u https://example.com -d 5 -jc | grep '\.js$' | tee alljs.txt  
		cat alljs.txt | uro | sort -u | httpx -mc 200 -o filteredJS.txt  

	Extract Secrets from JavaScript

		cat filteredJS.txt | jsleak -s -l -k  
		cat filteredJS.txt | nuclei -t ~/nuclei-templates/http/exposures/ -c 30

		cat filteredJS.txt | xargs -I {} curl -s {} | grep -E 'aws_access_key|aws_secret_key|api_key|passwd|password|db_password|sql_password|admin_pass|admin_password|root_pass|database_url|db_host|db_user|db_pass|gcp_key|firebase_api_key|google_api_key|htaccess|htpasswd|config.json|config.yml|secrets.yml|env|.env|credentials|private_key|jwt_secret|ssh_key|access_token|authorization|bearer_token|client_secret|consumer_secret|ftp_password|s3_bucket|s3_access_key|s3_secret_key|smtp_password|ldap_password' --color=auto | tee js_secrets.txt

🔹 Step 3: Sensitive File & Backup Discovery

		cat urls.txt | grep -E "\.zip|\.tar|\.gz|\.sql|\.backup|\.bak" | anew backups.txt  
		cat backups.txt | httpx -mc 200 -o valid_backups.txt  

		ffuf -w wordlists/sensitive-files.txt -u https://example.com/FUZZ -mc 200,302 -o sensitive_files.txt  

		cat urls.txt | grep -E "\.git|\.env|\.log|\.sql|\.bak|\.config|\.json|\.yml" | tee sensitive_ur

🔹 Step 4: Fuzzing for Sensitive Endpoints

		[i]WEB fuzzing ENDPOINTS

		1. Fuzz api.xyz.com/FUZZ

			ffuf -w /root/Desktop/payloads/useful/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -u https://admin.cloudamqp.com/FUZZ -mc 200


		2. Fuzz api.xyz.com/v8/FUZZ

			ffuf -w /opt/useful/SecLists/Discovery/Web-Content/dirsearch.txt -u https://api.xyz.com/v8/FUZZ -mc 200

		3. Fuzz api.xyz.com/FUZZ/v8

			ffuf -w /opt/useful/SecLists/Discovery/Web-Content/dirsearch.txt -u https://api.xyz.com/FUZZ/v8 -mc 200


		ffuf -w wordlists/directory-list-2.3-medium.txt -u https://example.com/FUZZ -mc 200,302 -o dir_enum.txt  

		ffuf -w wordlists/api-endpoints.txt -u https://example.com/FUZZ -mc 200 -o api_fuzz.txt  

🔹 Step 5: Exposed .env Files & Secrets

		cat urls.txt | grep ".env" | httpx -mc 200 -o env_found.txt  

		nuclei -l urls.txt -t /nuclei-templates/http/exposures/configs/ -o nuclei_env.txt  


- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 



		echo "https://example.com/" | waybackurls | anew urls.txt 
		httpx -l urls.txt -mc 200 -silent > filtered_urls.txt -rate-limit 1

		cat urls.txt | katana | hakrawler -d 3 | anew katana.txt -rate-limit 1
		[+]to get a unique path ->
		cat katana.txt urls.txt | unfurl format %p | anew paths.txt -rate-limit
	
		katana -u https://payroll.razorpay.com -d 5 -jc |grep '\.js$' | tee alljs.txt
		cat alljs.txt | uro  | sort -u | httpx -mc 200 -o filteredJS.txt
		cat filteredJS.txt| jsleak -s -l -k
		cat filteredJS.txt | nuclei -t /nuclei-templates/http/exposures -c 30
		cat filteredJS.txt | xargs -I {} curl -s {} | grep -E 'aws_access_key|aws_secret_key|api_key|passwd|password|db_password|sql_password|admin_pass|admin_password|root_pass|database_url|db_host|db_user|db_pass|gcp_key|firebase_api_key|google_api_key|htaccess|htpasswd|config.json|config.yml|secrets.yml|env|.env|credentials|private_key|jwt_secret|ssh_key|access_token|authorization|bearer_token|client_secret|consumer_secret|ftp_password|s3_bucket|s3_access_key|s3_secret_key|smtp_password|ldap_password' --color=auto

		

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
## nmap->
		nmap -p- -sV -O  152.16.201.145 --script vuln

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
## magic recon for wildcards->
		./magicrecon.sh -d www.target.com -a

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
## netlas
		Organization’s emails:  \*.contacts.email.keyword:*@target.com
		Organization’s details: registrant.organization:"Organization"
		Finding Subdomains:     domain:*.target.com
		Finding Nameservers:    name_servers:*.ns.target.com
		Finding SSL Certificates: certificate.subject.organization:"Target Organization"
		Exploring CVEs found in the organization’s application:   cve.description:"Target's Name"
	
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
## dirsearch
		python3 dirsearch.py -l target.txt --deep-recursive


[+]403 error or 404 on the webpage then try -> 
   	 	
   	 	python3 dirsearch.py -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,log,xml,js,json  -u https://target

    python3 dirsearch.py -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,log,xml,js,json  -u https://target/app
    
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
## import list of your domains in katana tool for crawling URLS
		cat domains.txt | katana | grep js | httpx -mc 200 | tee js.txt
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
## Scanning by nuclie
		nuclei -l js.txt -t ~/nuclei-templates/exposures/ -o js_bugs.txt
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

## Extracting all urls from JavaScript files
		cat subdomain.txt | katana -silent -d 7 -jc -jsl -kf robotstxt sitemapxml | tee urls.txt
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

##ffuf for hidden directory
		ffuf -u https://example.com/FUZZ -w /opt/useful/SecLists/Discovery/Web-Content/dirsearch.txt -t 50 -mc 200 -fc 403
		ffuf -u https://example.com/FUZZ -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -t 50 -mc 200 -fc 403
	
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

##💻Targeting GitHub for 💻
		
Manual Approach: 
		https://gist.github.com/search?l=JSON&q=%22.%2Atesla.com%22
		".*tesla.com"
		SECRET OR secret "tesla.com" 
		pass OR password OR passwd "indrive.com"
		credentials OR consumer_key "indrive.com"
		"indrive.com" login       
		"indrive.com" token
		"indrive.com" ftp
		"indrive.com" aws
		"indrive.com" config
		"indrive.com" ldap
		"indrive.com" jenkins
		tesla "-----BEGIN OPENSSH PRIVATE KEY-----"
		tesla "-----BEGIN CERTIFICATE-----"
		tesla "-----BEGIN PRIVATE KEY----"
		"DB_PASSWORD" OR "DATABASE_URL" OR "DATABASE_PASSWORD" OR "DBpasswd"  tesla.com 
		"Company" send_keys            | Password related keyword       | moderate     |
		"Company" QSqlDatabase         | Qt sql framework config        | moderate     |
		"Company" setPassword          | Qt sql password db config      | moderate     |
		"Company" send,keys OR key     | Password related keyword       | moderate     |
		"Company" apiKey OR api_token  | firebase config                | moderate     |
		"Company" databaseURL          | firebase config                | moderate     |
		"Company" storageBucket        | firebase config                | moderate     |

		"Company" security_credentials ---> LDAP ( active directories )

		"Company" connectionstring ---> Database Cred

		"Company" JDBC ---> Database Cred

		"Company" ssh2_auth_password ---> unautorized access to servers

		"Company" send_keys OR send,keys


		path:**/.npmrc _auth tasla.com NOT example.com
		path:*/*config.sh password tasla.com NOT example.com
		path:*.pem private key tasla.com
		path:src/*.js tasla.com
		"tasla"language:Python OR bash
		owner:octocat abc
		repo:repo owner name

		path:*.env ( NOT homestead NOT root NOT example NOT gmail NOT sample NOT localhost NOT marutise) password outlook.com

		(path:*.xml OR path:*.json OR path:*.properties OR path:*.txt OR path:*.log OR path:*.config OR path:*.conf OR path:*.cfg OR path:*.env OR path:*.envrc OR path:*.prod OR path:*.secret OR path:*.private OR path:*.key) AND (access_key OR secret_key OR access_token OR api_key OR apikey OR api_secret OR auth_token OR authsecret OR "sk-") AND (openai OR gpt) "tesla.com" NOT
		(homestead NOT root NOT example NOT gmail NOT sample NOT localhost NOT marutise)




