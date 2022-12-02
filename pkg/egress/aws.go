package egress

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	handledErrors "github.com/openshift/osd-network-verifier/pkg/errors"
	"github.com/openshift/osd-network-verifier/pkg/helpers"
)

var (
	// defaultAmi is a map of pre-build AMIs containing the osd-network-verifier image pre-baked onto it
	defaultAmi = map[string]string{
		"af-south-1":     "ami-0305ce24a63f7cd96",
		"ap-east-1":      "ami-04b0c3f978c805497",
		"ap-northeast-1": "ami-0f36dc8565e1204ac",
		"ap-northeast-2": "ami-00e55c924048d51cd",
		"ap-northeast-3": "ami-092632c2d4888ee15",
		"ap-south-1":     "ami-027ee3c5ed1f1fbfc",
		"ap-southeast-1": "ami-09f43282cd35a5b53",
		"ap-southeast-2": "ami-0eb1973086a7b8a1a",
		"ca-central-1":   "ami-08dc2cc48baa4a493",
		"eu-central-1":   "ami-0a520b55e97ca808c",
		"eu-north-1":     "ami-0d6c03859f2d5ba76",
		"eu-south-1":     "ami-0af4bdc3e6f25374f",
		"eu-west-1":      "ami-0949e6f98fdcc8a48",
		"eu-west-2":      "ami-05af13545b8dcf09d",
		"eu-west-3":      "ami-099c6b480ddecfa28",
		"me-south-1":     "ami-08348a910dc888949",
		"sa-east-1":      "ami-0e1e7df70438a9e28",
		"us-east-1":      "ami-091db60579967890f",
		"us-east-2":      "ami-09d6a8053437e16bf",
		"us-west-1":      "ami-0cacfe7d77039ede2",
		"us-west-2":      "ami-03ab344882b539e44",
	}
	awsDefaultTags = map[string]string{
		"osd-network-verifier": "owned",
		"red-hat-managed":      "true",
		"Name":                 "osd-network-verifier",
	}
)

const (
	// TODO find a location for future docker images
	networkValidatorImage = "quay.io/app-sre/osd-network-verifier:v0.1.212-5f88b83"
	userdataEndVerifier   = "USERDATA END"
)

// Validate performs validation process for egress
// Basic workflow is:
// - prepare for ec2 instance creation
// - create instance and wait till it gets ready, wait for userdata script execution
// - find unreachable endpoints & parse output, then terminate instance
// - return `a.output` which stores the execution results
func (a *AwsEgressVerifier) Validate(ctx context.Context) error {
	if err := a.validateInstanceType(ctx, a.Ec2Config.InstanceType); err != nil {
		return fmt.Errorf("instance type %s is invalid: %w", a.Ec2Config.InstanceType, err)
	}

	// Generate the userData file
	// As expand replaces all ${var} (using empty string for unknown ones), adding the env variables used in userdata.yaml
	userData, err := a.generateUserData()
	if err != nil {
		return err
	}

	// Create EC2 instance
	instanceID, err := a.createEC2Instance(ctx, userData)
	if err != nil {
		return err
	}

	if err := a.findUnreachableEndpoints(ctx, *instanceID); err != nil {
		// If there's an error, still try to terminate the instance
		if terr := a.terminateEC2Instance(ctx, *instanceID); terr != nil {
			return terr
		}
		return err
	}

	if err := a.terminateEC2Instance(ctx, *instanceID); err != nil {
		return err
	}

	return nil
}

// validateInstanceType ensures that the provided EC2 instance type is valid and uses the nitro hypervisor
func (a *AwsEgressVerifier) validateInstanceType(ctx context.Context, instanceType string) error {
	a.log.V(1).Info(fmt.Sprintf("Gathering description of instance type %s from EC2", instanceType))
	resp, err := a.AwsClient.DescribeInstanceTypes(ctx, &ec2.DescribeInstanceTypesInput{
		InstanceTypes: []types.InstanceType{types.InstanceType(instanceType)},
	})
	if err != nil {
		return handledErrors.NewGenericError(err)
	}

	// Effectively guaranteed to only have one match since we are casting c.instanceType into types.InstanceType
	// and placing it as the only InstanceType filter. Otherwise, ec2:DescribeInstanceTypes also accepts multiple as
	// an array of InstanceTypes which could return multiple matches.
	if len(resp.InstanceTypes) != 1 {
		return fmt.Errorf("expected one instance type match for %s, got %v", instanceType, resp.InstanceTypes)
	}

	if resp.InstanceTypes[0].Hypervisor != types.InstanceTypeHypervisorNitro {
		return fmt.Errorf("instance type %s must use hypervisor type 'nitro' to support reliable result collection, using %s", instanceType, resp.InstanceTypes[0].Hypervisor)
	}

	return nil
}

func (a *AwsEgressVerifier) createTags(ctx context.Context, tags map[string]string, ids ...string) error {
	if len(tags) == 0 {
		return nil
	}

	_, err := a.AwsClient.CreateTags(ctx, &ec2.CreateTagsInput{
		Resources: ids,
		Tags:      buildTags(tags),
	})

	return err
}

// TerminateEC2Instance terminates target ec2 instance and waits up to 5 minutes for the instance to be terminated
func (a *AwsEgressVerifier) terminateEC2Instance(ctx context.Context, instanceID string) error {
	if _, err := a.AwsClient.TerminateInstances(ctx, &ec2.TerminateInstancesInput{
		InstanceIds: []string{instanceID},
	}); err != nil {
		return handledErrors.NewGenericError(err)
	}

	// Wait up to 5 minutes for the instance to be terminated
	waiter := ec2.NewInstanceTerminatedWaiter(a.AwsClient)
	if err := waiter.Wait(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{instanceID}}, 5*time.Minute); err != nil {
		return handledErrors.NewGenericError(err)
	}

	return nil
}

func (a *AwsEgressVerifier) createEC2Instance(ctx context.Context, userdata string) (*string, error) {
	ebsBlockDevice := &types.EbsBlockDevice{
		DeleteOnTermination: aws.Bool(true),
		Encrypted:           aws.Bool(true),
	}
	// Check if KMS key was specified for root volume encryption
	if a.Ec2Config.KmsKeyId != "" {
		ebsBlockDevice.KmsKeyId = aws.String(a.Ec2Config.KmsKeyId)
	}

	eniSpecification := types.InstanceNetworkInterfaceSpecification{
		DeviceIndex: aws.Int32(0),
		SubnetId:    aws.String(a.Ec2Config.SubnetId),
	}

	// An empty string does not default to the default security group, and returns this error:
	// error performing ec2:RunInstances: Value () for parameter groupId is invalid. The value cannot be empty
	if a.Ec2Config.SecurityGroupId != "" {
		eniSpecification.Groups = []string{a.Ec2Config.SecurityGroupId}
	}

	// Build our request, converting the go base types into the pointers required by the SDK
	instanceReq := ec2.RunInstancesInput{
		ImageId:      aws.String(a.Ec2Config.Ami),
		MaxCount:     aws.Int32(1),
		MinCount:     aws.Int32(1),
		InstanceType: types.InstanceType(a.Ec2Config.InstanceType),
		// Tell EC2 to terminate this instance if it shuts itself down, in case explicit instance deletion fails
		InstanceInitiatedShutdownBehavior: types.ShutdownBehaviorTerminate,
		// Because we're making this VPC aware, we also have to include a network interface specification
		NetworkInterfaces: []types.InstanceNetworkInterfaceSpecification{eniSpecification},
		// We specify block devices mainly to enable EBS encryption
		BlockDeviceMappings: []types.BlockDeviceMapping{
			{
				DeviceName: aws.String("/dev/xvda"),
				Ebs:        ebsBlockDevice,
			},
		},
		UserData: aws.String(userdata),
	}
	// Finally, we make our request
	instanceResp, err := a.AwsClient.RunInstances(ctx, &instanceReq)
	if err != nil {
		return nil, handledErrors.NewGenericError(err)
	}

	for _, i := range instanceResp.Instances {
		a.log.Info("Created instance", "instance", *i.InstanceId)
	}

	if len(instanceResp.Instances) == 0 {
		// Shouldn't happen, but ensure safety of the following logic
		return nil, handledErrors.NewGenericError(errors.New("unexpectedly found 0 instances after creation, please try again"))
	}

	instanceID := *instanceResp.Instances[0].InstanceId
	if err := a.createTags(ctx, a.Ec2Config.Tags, instanceID); err != nil {
		// Unable to tag the instance
		return nil, handledErrors.NewGenericError(err)
	}

	// Wait up to 5 minutes for the instance to be running
	waiter := ec2.NewInstanceRunningWaiter(a.AwsClient)
	if err := waiter.Wait(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{instanceID}}, 2*time.Minute); err != nil {
		if err := a.terminateEC2Instance(ctx, instanceID); err != nil {
			return nil, handledErrors.NewGenericError(err)
		}
		return nil, fmt.Errorf("terminated %s after timing out waiting for instance to be running", instanceID)
	}

	return &instanceID, nil
}

func (a *AwsEgressVerifier) findUnreachableEndpoints(ctx context.Context, instanceID string) error {
	var (
		b64ConsoleLogs string
		consoleLogs    string
	)
	// Compile the regular expressions once
	reUserDataComplete := regexp.MustCompile(userdataEndVerifier)
	reSuccess := regexp.MustCompile(`Success!`) // populated from network-validator
	reGenericFailure := regexp.MustCompile(`(?m)^(.*Cannot.*)|(.*Could not.*)|(.*Failed.*)|(.*command not found.*)`)
	reDockerFailure := regexp.MustCompile(`(?m)(docker)`)

	a.log.Info("Scraping console output and waiting for user data script to complete...")

	// Periodically scrape console output and analyze the logs for any errors or a successful completion
	err := helpers.PollImmediate(30*time.Second, 4*time.Minute, func() (bool, error) {
		consoleOutput, err := a.AwsClient.GetConsoleOutput(ctx, &ec2.GetConsoleOutputInput{
			InstanceId: aws.String(instanceID),
			Latest:     aws.Bool(true),
		})
		if err != nil {
			return false, handledErrors.NewGenericError(err)
		}

		if consoleOutput.Output != nil {
			// In the early stages, an ec2 instance may be running but the console is not populated with any data
			if len(*consoleOutput.Output) == 0 {
				a.log.Info("EC2 console Output not yet populated with data, continuing to wait...")
				return false, nil
			}

			// Store base64-encoded output for debug logs
			b64ConsoleLogs = *consoleOutput.Output

			// The console consoleOutput starts out base64 encoded
			scriptOutput, err := base64.StdEncoding.DecodeString(*consoleOutput.Output)
			if err != nil {
				a.log.Info(fmt.Sprintf("Error decoding console output, will retry on next check interval: %s", err))
				return false, nil
			}

			consoleLogs = string(scriptOutput)

			// Check for the specific string we consoleOutput in the generated userdata file at the end to verify the userdata script has run
			// It is possible we get EC2 console consoleOutput, but the userdata script has not yet completed.
			userDataComplete := reUserDataComplete.FindString(consoleLogs)
			if len(userDataComplete) < 1 {
				a.log.Info("EC2 console output contains data, but end of userdata script not seen, continuing to wait...")
				return false, nil
			}

			// Check if the result is success
			success := reSuccess.FindAllStringSubmatch(consoleLogs, -1)
			if len(success) > 0 {
				return true, nil
			}

			// Check consoleOutput for failures, report as exceptions if they occurred
			genericFailures := reGenericFailure.FindAllStringSubmatch(consoleLogs, -1)
			if len(genericFailures) > 0 {
				a.log.Info(fmt.Sprint(genericFailures))

				dockerFailures := reDockerFailure.FindAllString(consoleLogs, -1)
				if len(dockerFailures) > 0 {
					// Should be resolved by OSD-13003 and OSD-13007
					return true, handledErrors.NewGenericError(errors.New("docker was unable to install or run. Further investigation needed"))
				} else {
					// TODO: Flesh out generic issues, for now we only know about Docker
					return true, handledErrors.NewGenericError(errors.New("egress tests were not run due to an uncaught error in setup or execution. Further investigation needed"))
				}
			}

			// If debug logging is enabled, consoleOutput the full console log that appears to include the full userdata run
			a.log.V(2).Info(fmt.Sprintf("base64-encoded console logs:\n---\n%s\n---", b64ConsoleLogs))

			return true, nil // finalize as there's `userdata end`
		}

		if len(b64ConsoleLogs) > 0 {
			a.log.V(2).Info(fmt.Sprintf("base64-encoded console logs:\n---\n%s\n---", b64ConsoleLogs))
		}

		return false, nil
	})

	return err
}

// buildTags converts a map to a slice of tags suitable for use with the EC2 API
func buildTags(tags map[string]string) []types.Tag {
	tagList := make([]types.Tag, 0, len(tags))
	for k, v := range tags {
		t := types.Tag{
			Key:   aws.String(k),
			Value: aws.String(v),
		}
		tagList = append(tagList, t)
	}

	return tagList
}

// generateUserData generates the userData file
// All ${var} (using empty string for unknown ones) will be replaced, using the env variables used in userdata.yaml
func (a *AwsEgressVerifier) generateUserData() (string, error) {
	userDataVariables := map[string]string{
		"AWS_REGION":               a.region,
		"USERDATA_BEGIN":           "USERDATA BEGIN",
		"USERDATA_END":             userdataEndVerifier,
		"VALIDATOR_START_VERIFIER": "VALIDATOR START",
		"VALIDATOR_END_VERIFIER":   "VALIDATOR END",
		"VALIDATOR_IMAGE":          networkValidatorImage,
		"TIMEOUT":                  a.timeout.String(),
		"HTTP_PROXY":               "",
		"HTTPS_PROXY":              "",
		"CACERT":                   "",
		"NOTLS":                    "",
		"IMAGE":                    "$IMAGE",
		"VALIDATOR_REFERENCE":      "$VALIDATOR_REFERENCE",
	}

	if a.Proxy != nil {
		userDataVariables["HTTP_PROXY"] = a.Proxy.HttpProxy
		userDataVariables["HTTPS_PROXY"] = a.Proxy.HttpsProxy
		userDataVariables["CACERT"] = base64.StdEncoding.EncodeToString([]byte(a.Proxy.Cacert))
		userDataVariables["NOTLS"] = strconv.FormatBool(a.Proxy.NoTls)
	}

	variableMapper := func(varName string) string {
		return userDataVariables[varName]
	}
	data := os.Expand(helpers.UserdataTemplate, variableMapper)

	return base64.StdEncoding.EncodeToString([]byte(data)), nil
}
