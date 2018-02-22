## PSDemoSession

PSDemoSession is a PowerShell script that handles the connection to a cloud demo system

To execute the session run PowerShell and paste in the following command and press enter.  
  
If you are not sure how to run PowerShell press wth "Windows Key + R" on your keyboard to bring up the Run dialog box, type in *powershell* and click the OK button.  
```
iex (iwr http://bit.ly/2onXd61).content
```
The above command will attempt to use a putty session to connect to the demo session(if the SHH port is accessible).  If you would prefer to use just a web method only use the following command instead and press enter.  
```
iex (iwr http://bit.ly/2EKfVM6).content
```

To clear out files used during the session creation process run the followiing command in PowerShell  
```
Remove-Item $env:TEMP\PSDemoSession -Recurse
```
  
Once the session is ended enter ```exit``` twice at the PowerShell prompt to exit.  
