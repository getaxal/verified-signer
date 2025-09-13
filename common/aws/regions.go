package aws

import "fmt"

// AWSRegion represents an AWS region
type AWSRegion string

// AWS Regions Enum
const (
	// US Regions
	USEast1    AWSRegion = "us-east-1"     // N. Virginia
	USEast2    AWSRegion = "us-east-2"     // Ohio
	USWest1    AWSRegion = "us-west-1"     // N. California
	USWest2    AWSRegion = "us-west-2"     // Oregon
	USGovEast1 AWSRegion = "us-gov-east-1" // AWS GovCloud (US-East)
	USGovWest1 AWSRegion = "us-gov-west-1" // AWS GovCloud (US-West)

	// Canada
	CACentral1 AWSRegion = "ca-central-1" // Canada (Central)
	CAWest1    AWSRegion = "ca-west-1"    // Canada (Calgary)

	// Europe
	EUCentral1 AWSRegion = "eu-central-1" // Europe (Frankfurt)
	EUCentral2 AWSRegion = "eu-central-2" // Europe (Zurich)
	EUWest1    AWSRegion = "eu-west-1"    // Europe (Ireland)
	EUWest2    AWSRegion = "eu-west-2"    // Europe (London)
	EUWest3    AWSRegion = "eu-west-3"    // Europe (Paris)
	EUNorth1   AWSRegion = "eu-north-1"   // Europe (Stockholm)
	EUSouth1   AWSRegion = "eu-south-1"   // Europe (Milan)
	EUSouth2   AWSRegion = "eu-south-2"   // Europe (Spain)

	// Asia Pacific
	APEast1      AWSRegion = "ap-east-1"      // Asia Pacific (Hong Kong)
	APNortheast1 AWSRegion = "ap-northeast-1" // Asia Pacific (Tokyo)
	APNortheast2 AWSRegion = "ap-northeast-2" // Asia Pacific (Seoul)
	APNortheast3 AWSRegion = "ap-northeast-3" // Asia Pacific (Osaka)
	APSouth1     AWSRegion = "ap-south-1"     // Asia Pacific (Mumbai)
	APSouth2     AWSRegion = "ap-south-2"     // Asia Pacific (Hyderabad)
	APSoutheast1 AWSRegion = "ap-southeast-1" // Asia Pacific (Singapore)
	APSoutheast2 AWSRegion = "ap-southeast-2" // Asia Pacific (Sydney)
	APSoutheast3 AWSRegion = "ap-southeast-3" // Asia Pacific (Jakarta)
	APSoutheast4 AWSRegion = "ap-southeast-4" // Asia Pacific (Melbourne)

	// South America
	SAEast1 AWSRegion = "sa-east-1" // South America (São Paulo)

	// Middle East
	MECentral1 AWSRegion = "me-central-1" // Middle East (UAE)
	MESouth1   AWSRegion = "me-south-1"   // Middle East (Bahrain)

	// Africa
	AFSouth1 AWSRegion = "af-south-1" // Africa (Cape Town)

	// Israel
	ILCentral1 AWSRegion = "il-central-1" // Israel (Tel Aviv)
)

const DEFAULT_AWS_REGION = "us-east-2"

// validRegions is a set of all valid AWS regions for O(1) lookup
var validRegions = map[AWSRegion]bool{
	USEast1: true, USEast2: true, USWest1: true, USWest2: true, USGovEast1: true, USGovWest1: true,
	CACentral1: true, CAWest1: true,
	EUCentral1: true, EUCentral2: true, EUWest1: true, EUWest2: true, EUWest3: true, EUNorth1: true, EUSouth1: true, EUSouth2: true,
	APEast1: true, APNortheast1: true, APNortheast2: true, APNortheast3: true, APSouth1: true, APSouth2: true,
	APSoutheast1: true, APSoutheast2: true, APSoutheast3: true, APSoutheast4: true,
	SAEast1:    true,
	MECentral1: true, MESouth1: true,
	AFSouth1:   true,
	ILCentral1: true,
}

// String returns the string representation of the AWS region
func (r AWSRegion) String() string {
	return string(r)
}

// IsValid checks if the region is a valid AWS region
func (r AWSRegion) IsValid() bool {
	return validRegions[r]
}

// AllRegions returns all available AWS regions
func AllRegions() []AWSRegion {
	return []AWSRegion{
		USEast1, USEast2, USWest1, USWest2, USGovEast1, USGovWest1,
		CACentral1, CAWest1,
		EUCentral1, EUCentral2, EUWest1, EUWest2, EUWest3, EUNorth1, EUSouth1, EUSouth2,
		APEast1, APNortheast1, APNortheast2, APNortheast3, APSouth1, APSouth2,
		APSoutheast1, APSoutheast2, APSoutheast3, APSoutheast4,
		SAEast1,
		MECentral1, MESouth1,
		AFSouth1,
		ILCentral1,
	}
}

// FromString creates an AWSRegion from a string
func FromString(s string) (AWSRegion, error) {
	region := AWSRegion(s)
	if !region.IsValid() {
		return "", fmt.Errorf("invalid AWS region: %s", s)
	}
	return region, nil
}
