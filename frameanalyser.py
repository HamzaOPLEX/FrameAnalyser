from prettytable import PrettyTable
from pprint import pprint

Codes = {'0800':'IPV4','86dd':'IPV6','0806':'ARP','06':'TCP','11':'UDP'}
frame = '984827225faa00262d969994080045000029209f400080060000c0a80165acd91224d86801bb2da4675fc7d65ab050103f608126000000'
prettyframe =  [frame[i:i+2] for i in range(0, len(frame), 2)]
n = 16
row = [prettyframe[i:i+n] for i in range(0, len(prettyframe), n)]

for r in row : 
	if len(r) < 15 :
		while len(r) < 16 :
			r.append('')

def FrameTable():
	x = PrettyTable()
	x.field_names = [i for i in range(0,16)]

	for i in range(len(row)):
		try : 
			x.add_row(row[i])
		except Exception as Err:
			pass
	return x


def extractData():
	def Hex2IP(IP) : 
		SplitIP = IP.split('.')
		NewIP = []
		for i in SplitIP :
			HexCalcule = int(i,16)
			NewIP.append(str(HexCalcule))
		ADDR = '.'.join(NewIP)
		return ADDR

	if ''.join(row[0][12:14]) == '0800' :
		SourceIP = Hex2IP('.'.join(row[1][10:14]))
		DestIP = Hex2IP(f"{'.'.join(row[1][14:16])}.{'.'.join(row[2][0:2])}")
		ExtratedDataIPV4 = {
			'DestMac' : ':'.join(row[0][0:6]),
			'SourceMac': ':'.join(row[0][6:12]),
			'FrameType' : Codes[''.join(row[0][12:14])],
			'ProtoType': Codes[row[1][7]],
			'SourceIP' : SourceIP,
			'DestIP' : DestIP,
			'SourcePort' : int(''.join(row[2][2:4]),16), # Convert From Hex2Decimal
			'DestPort' : int(''.join(row[2][4:6]),16)	 # Convert From Hex2Decimal
		}
		return ExtratedDataIPV4
	else :
		return False
Table = FrameTable()

Data = extractData()
if Data == False: 
	print(f"{Codes[''.join(row[0][12:14])]} FrameType is comming Soon :)")
else: 
	pprint(Data)