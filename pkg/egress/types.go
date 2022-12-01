package egress

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
)

// Validator defines the behaviors necessary to run verifier completely. Any clients that use that fullfills this interface
// will be able to run all verifier test
type Validator interface {
	// Validate validates that all required targets are reachable from the vpcsubnet
	// target URLs: https://docs.openshift.com/rosa/rosa_getting_started/rosa-aws-prereqs.html#osd-aws-privatelink-firewall-prerequisites
	Validate(ctx context.Context) error
}

type AwsClient interface {
	CreateTags(ctx context.Context, params *ec2.CreateTagsInput, optFns ...func(options *ec2.Options)) (*ec2.CreateTagsOutput, error)
	ec2.DescribeInstancesAPIClient
	ec2.DescribeInstanceTypesAPIClient
	GetConsoleOutput(ctx context.Context, params *ec2.GetConsoleOutputInput, optFns ...func(options *ec2.Options)) (*ec2.GetConsoleOutputOutput, error)
	RunInstances(ctx context.Context, params *ec2.RunInstancesInput, optFns ...func(options *ec2.Options)) (*ec2.RunInstancesOutput, error)
	TerminateInstances(ctx context.Context, params *ec2.TerminateInstancesInput, optFns ...func(options *ec2.Options)) (*ec2.TerminateInstancesOutput, error)
}

type Ec2Config struct {
	Ami             string
	InstanceType    string
	KmsKeyId        string
	SecurityGroupId string
	SubnetId        string
	Tags            map[string]string
}

type Proxy struct {
	HttpProxy  string
	HttpsProxy string
	Cacert     string
	NoTls      bool
}

type AwsEgressVerifier struct {
	AwsClient AwsClient
	Ec2Config *Ec2Config
	Proxy     *Proxy
	region    string
	timeout   time.Duration

	log logr.Logger
}

// NewDefaultAwsEgressVerifier assembles an AwsEgressVerifier given an aws-sdk-go-v2 Config
func NewDefaultAwsEgressVerifier(cfg aws.Config) (*AwsEgressVerifier, error) {
	zapLog, err := zap.NewDevelopment()
	if err != nil {
		return nil, err
	}

	ami, ok := defaultAmi[cfg.Region]
	if !ok {
		return nil, fmt.Errorf("unsupported region: %s", cfg.Region)
	}

	return &AwsEgressVerifier{
		Ec2Config: &Ec2Config{
			Ami:          ami,
			InstanceType: "t3.micro",
			Tags:         awsDefaultTags,
		},
		region:    cfg.Region,
		timeout:   2 * time.Second,
		AwsClient: ec2.NewFromConfig(cfg),
		log:       zapr.NewLogger(zapLog),
	}, nil
}
