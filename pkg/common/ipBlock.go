package common

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
)

const (
	ipByte         = 0xff
	ipShift0       = 24
	ipShift1       = 16
	ipShift2       = 8
	ipBase         = 10
	ipMask         = 0xffffffff
	maxIPv4Bits    = 32
	CidrAll        = "0.0.0.0/0"
	cidrSeparator  = "/"
	bitSize64      = 64
	commaSeparator = ", "
)

// IPBlock captures a set of ip ranges
type IPBlock struct {
	ipRange CanonicalIntervalSet
}

// ToIPRanges returns a string of the ip ranges in the current IPBlock object
func (b *IPBlock) ToIPRanges() string {
	return strings.Join(b.ToIPRangesList(), commaSeparator)
}

// ToIPRange returns a string of the ip range of a single interval
func toIPRange(i Interval) string {
	startIP := InttoIP4(i.Start)
	endIP := InttoIP4(i.End)
	return rangeIPstr(startIP, endIP)
}

// ToIPRangesList: returns a list of the ip-ranges strings in the current IPBlock object
func (b *IPBlock) ToIPRangesList() []string {
	IPRanges := make([]string, len(b.ipRange.IntervalSet))
	for index := range b.ipRange.IntervalSet {
		IPRanges[index] = toIPRange(b.ipRange.IntervalSet[index])
	}
	return IPRanges
}

// IsIPAddress returns true if IPBlock object is a range of exactly one ip address from input
func (b *IPBlock) IsIPAddress(ipAddress string) bool {
	ipRanges := b.ToIPRanges()
	return ipRanges == rangeIPstr(ipAddress, ipAddress)
}

func (b *IPBlock) ContainedIn(c *IPBlock) bool {
	return b.ipRange.ContainedIn(c.ipRange)
}

func (b *IPBlock) Intersection(c *IPBlock) *IPBlock {
	res := &IPBlock{}
	res.ipRange = b.ipRange.Copy()
	res.ipRange.Intersection(c.ipRange)
	return res
}

func (b *IPBlock) Equal(c *IPBlock) bool {
	return b.ipRange.Equal(c.ipRange)
}

func (b *IPBlock) Subtract(c *IPBlock) *IPBlock {
	res := &IPBlock{}
	res.ipRange = b.ipRange.Copy()
	res.ipRange.Subtraction(c.ipRange)
	return res
}

func (b *IPBlock) Union(c *IPBlock) *IPBlock {
	res := &IPBlock{}
	res.ipRange = b.ipRange.Copy()
	res.ipRange.Union(c.ipRange)
	return res
}

func (b *IPBlock) Empty() bool {
	return b.ipRange.IsEmpty()
}

func rangeIPstr(start, end string) string {
	return fmt.Sprintf("%v-%v", start, end)
}

// Copy returns a new copy of IPBlock object
func (b *IPBlock) Copy() *IPBlock {
	res := &IPBlock{}
	res.ipRange = b.ipRange.Copy()
	return res
}

func (b *IPBlock) ipCount() int {
	res := 0
	for _, r := range b.ipRange.IntervalSet {
		res += int(r.End) - int(r.Start) + 1
	}
	return res
}

func (b *IPBlock) StartIPNum() int64 {
	return b.ipRange.IntervalSet[0].Start
}

// Split returns a set of IpBlock objects, each with a single range of ips
func (b *IPBlock) Split() []*IPBlock {
	res := make([]*IPBlock, len(b.ipRange.IntervalSet))
	for index, ipr := range b.ipRange.IntervalSet {
		newBlock := IPBlock{}
		newBlock.ipRange.IntervalSet = append(newBlock.ipRange.IntervalSet, Interval{Start: ipr.Start, End: ipr.End})
		res[index] = &newBlock
	}
	return res
}

// InttoIP4 returns a string of an ip address from an input integer ip value
func InttoIP4(ipInt int64) string {
	// need to do two bit shifting and “0xff” masking
	b0 := strconv.FormatInt((ipInt>>ipShift0)&ipByte, ipBase)
	b1 := strconv.FormatInt((ipInt>>ipShift1)&ipByte, ipBase)
	b2 := strconv.FormatInt((ipInt>>ipShift2)&ipByte, ipBase)
	b3 := strconv.FormatInt((ipInt & ipByte), ipBase)
	return b0 + "." + b1 + "." + b2 + "." + b3
}

// DisjointIPBlocks returns an IPBlock of disjoint ip ranges from 2 input IPBlock objects
func DisjointIPBlocks(set1, set2 []*IPBlock) []*IPBlock {
	ipbList := []*IPBlock{}
	for _, ipb := range set1 {
		ipbList = append(ipbList, ipb.Copy())
	}
	for _, ipb := range set2 {
		ipbList = append(ipbList, ipb.Copy())
	}
	// sort ipbList by ip_count per ipblock
	sort.Slice(ipbList, func(i, j int) bool {
		return ipbList[i].ipCount() < ipbList[j].ipCount()
	})
	// making sure the resulting list does not contain overlapping ipBlocks
	blocksWithNoOverlaps := []*IPBlock{}
	for _, ipb := range ipbList {
		blocksWithNoOverlaps = addIntervalToList(ipb, blocksWithNoOverlaps)
	}

	res := blocksWithNoOverlaps
	if len(res) == 0 {
		newAll, _ := NewIPBlock("0.0.0.0/0", []string{})
		res = append(res, newAll)
	}
	return res
}

// addIntervalToList is used for computation of DisjointIPBlocks
func addIntervalToList(ipbNew *IPBlock, ipbList []*IPBlock) []*IPBlock {
	toAdd := []*IPBlock{}
	for idx, ipb := range ipbList {
		if !ipb.ipRange.Overlaps(&ipbNew.ipRange) {
			continue
		}
		intersection := ipb.Copy()
		intersection.ipRange.Intersection(ipbNew.ipRange)
		ipbNew.ipRange.Subtraction(intersection.ipRange)
		if !ipb.ipRange.Equal(intersection.ipRange) {
			toAdd = append(toAdd, intersection)
			ipbList[idx].ipRange.Subtraction(intersection.ipRange)
		}
		if len(ipbNew.ipRange.IntervalSet) == 0 {
			break
		}
	}
	ipbList = append(ipbList, ipbNew.Split()...)
	ipbList = append(ipbList, toAdd...)
	return ipbList
}

func NewIPBlockFromCidr(cidr string) *IPBlock {
	res, err := NewIPBlock(cidr, []string{})
	if err != nil {
		return nil
	}
	return res
}

func NewIPBlockFromCidrOrAddress(s string) *IPBlock {
	var res *IPBlock
	if strings.Contains(s, cidrSeparator) {
		res = NewIPBlockFromCidr(s)
	} else {
		res, _ = NewIPBlockFromIPAddress(s)
	}
	return res
}

// NewIPBlockFromCidrList returns IPBlock object from multiple CIDRs given as list of strings
func NewIPBlockFromCidrList(cidrsList []string) *IPBlock {
	res := &IPBlock{ipRange: CanonicalIntervalSet{}}
	for _, cidr := range cidrsList {
		block := NewIPBlockFromCidr(cidr)
		res = res.Union(block)
	}
	return res
}

// NewIPBlock returns an IPBlock object from input cidr str an exceptions cidr str
func NewIPBlock(cidr string, exceptions []string) (*IPBlock, error) {
	res := IPBlock{ipRange: CanonicalIntervalSet{}}
	interval, err := cidrToInterval(cidr)
	if err != nil {
		return nil, err
	}
	res.ipRange.AddInterval(*interval)
	for i := range exceptions {
		intervalHole, err := cidrToInterval(exceptions[i])
		if err != nil {
			return nil, err
		}
		res.ipRange.AddHole(*intervalHole)
	}
	return &res, nil
}

func IPv4AddressToCidr(ipAddress string) string {
	return ipAddress + "/32"
}

// NewIPBlockFromIPAddress returns an IPBlock object from input ip address str
func NewIPBlockFromIPAddress(ipAddress string) (*IPBlock, error) {
	return NewIPBlock(IPv4AddressToCidr(ipAddress), []string{})
}

func cidrToIPRange(cidr string) (start, end int64, err error) {
	// convert string to IPNet struct
	_, ipv4Net, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}

	// convert IPNet struct mask and address to uint32
	// network is BigEndian
	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	startNum := binary.BigEndian.Uint32(ipv4Net.IP)
	// find the final address
	endNum := (startNum & mask) | (mask ^ ipMask)
	start = int64(startNum)
	end = int64(endNum)
	return
}

func cidrToInterval(cidr string) (*Interval, error) {
	start, end, err := cidrToIPRange(cidr)
	if err != nil {
		return nil, err
	}
	return &Interval{Start: start, End: end}, nil
}

func (b *IPBlock) ToCidrList() []string {
	cidrList := []string{}
	for _, interval := range b.ipRange.IntervalSet {
		cidrList = append(cidrList, IntervalToCidrList(interval.Start, interval.End)...)
	}
	return cidrList
}

// ToCidrListString returns a string with all CIDRs within the IPBlock object
func (b *IPBlock) ToCidrListString() string {
	return strings.Join(b.ToCidrList(), commaSeparator)
}

// ListToPrint: returns a uniform to print list s.t. each element contains either a single cidr or an ip range
func (b *IPBlock) ListToPrint() []string {
	cidrsIPRangesList := []string{}
	for _, interval := range b.ipRange.IntervalSet {
		cidr := IntervalToCidrList(interval.Start, interval.End)
		if len(cidr) == 1 {
			cidrsIPRangesList = append(cidrsIPRangesList, cidr[0])
		} else {
			cidrsIPRangesList = append(cidrsIPRangesList, toIPRange(interval))
		}
	}
	return cidrsIPRangesList
}

func (b *IPBlock) ToIPAdress() string {
	if b.ipRange.isSingleNumber() {
		return InttoIP4(b.ipRange.IntervalSet[0].Start)
	}
	return ""
}

func IntervalToCidrList(ipStart, ipEnd int64) []string {
	start := ipStart
	end := ipEnd
	res := []string{}
	for end >= start {
		maxSize := maxIPv4Bits
		for maxSize > 0 {
			s := maxSize - 1
			mask := int64(math.Round(math.Pow(2, maxIPv4Bits) - math.Pow(2, float64(maxIPv4Bits)-float64(s))))
			maskBase := start & mask
			if maskBase != start {
				break
			}
			maxSize--
		}
		x := math.Log(float64(end)-float64(start)+1) / math.Log(2)
		maxDiff := byte(maxIPv4Bits - math.Floor(x))
		if maxSize < int(maxDiff) {
			maxSize = int(maxDiff)
		}
		ip := InttoIP4(start)
		res = append(res, fmt.Sprintf("%s/%d", ip, maxSize))
		start += int64(math.Pow(2, maxIPv4Bits-float64(maxSize)))
	}
	return res
}

func IPBlockFromIPRangeStr(ipRagneStr string) (*IPBlock, error) {
	ipAddresses := strings.Split(ipRagneStr, "-")
	if len(ipAddresses) != 2 {
		return nil, errors.New("unexpected ipRange str")
	}
	var startIP, endIP *IPBlock
	var err error
	if startIP, err = NewIPBlockFromIPAddress(ipAddresses[0]); err != nil {
		return nil, err
	}
	if endIP, err = NewIPBlockFromIPAddress(ipAddresses[1]); err != nil {
		return nil, err
	}
	res := &IPBlock{}
	res.ipRange = CanonicalIntervalSet{IntervalSet: []Interval{}}
	startIPNum := startIP.ipRange.IntervalSet[0].Start
	endIPNum := endIP.ipRange.IntervalSet[0].Start
	res.ipRange.IntervalSet = append(res.ipRange.IntervalSet, Interval{Start: startIPNum, End: endIPNum})
	return res, nil
}

func GetCidrAll() *IPBlock {
	return NewIPBlockFromCidr(CidrAll)
}

func IsAddressInSubnet(address, subnetCidr string) (bool, error) {
	var addressIPblock, subnetIPBlock *IPBlock
	var err error
	if addressIPblock, err = NewIPBlockFromIPAddress(address); err != nil {
		return false, err
	}
	subnetIPBlock = NewIPBlockFromCidr(subnetCidr)
	return addressIPblock.ContainedIn(subnetIPBlock), nil
}

func CIDRtoIPrange(cidr string) string {
	ipb := NewIPBlockFromCidr(cidr)
	return ipb.ToIPRanges()
}

// PrefixLength returns the cidr's prefix length, assuming the ipBlock is exactly one cidr.
// Prefix length specifies the number of bits in the IP address that are to be used as the subnet mask.
func (b *IPBlock) PrefixLength() (int64, error) {
	cidrs := b.ToCidrList()
	if len(cidrs) != 1 {
		return 0, errors.New("prefixLength err: ipBlock is not a single cidr")
	}
	cidrStr := cidrs[0]
	lenStr := strings.Split(cidrStr, cidrSeparator)[1]
	return strconv.ParseInt(lenStr, ipBase, bitSize64)
}
