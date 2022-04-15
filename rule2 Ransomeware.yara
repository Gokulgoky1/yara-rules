rule ransomeware
{
	meta:
	description="This rule will find ransomeware "
	strings:
	$a="count.exe"
	$b= "https://blockchain.info/payment_request?address=17ZQaThXQmUN4MdhtRvcuJ36XtuDs6USLk&amount=0.2&message=pay%200.2%20bitcoin%20and%20receive%20a%20decrypting%20code"
	//will makes connection to above url
	condition:
	($a and $b)
} 