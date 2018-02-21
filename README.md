## PSDemoSession

PSDemoSession is a PowerShell script that handles the connection to a cloud demo system

To execute the session run PowerShell and paste in the following command and press enter  
```
iex (iwr http://bit.ly/2onXd61).content
```
  
To clear out files used during the session creation process run the followiing command in PowerShell  
```
Remove-Item $env:TEMP\PSDemoSession -Recurse
```
  
Once the session is ended enter ```exit``` twice at the PowerShell prompt to exit.  