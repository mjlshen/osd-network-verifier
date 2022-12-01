module github.com/openshift/osd-network-verifier

go 1.16

require (
	cloud.google.com/go/compute v1.7.0 // indirect
	github.com/aws/aws-sdk-go-v2 v1.11.2
	github.com/aws/aws-sdk-go-v2/config v1.10.3
	github.com/aws/aws-sdk-go-v2/credentials v1.6.4
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.24.0
	github.com/aws/smithy-go v1.9.0
	github.com/go-logr/logr v1.2.3
	github.com/go-logr/zapr v1.2.3
	github.com/openshift-online/ocm-cli v0.1.64
	github.com/openshift-online/ocm-sdk-go v0.1.273
	go.uber.org/zap v1.19.0
	golang.org/x/oauth2 v0.0.0-20220608161450-d0670ef3b1eb
	google.golang.org/api v0.84.0
)
