```log
00000008	159.96389771	========================================	
00000009	159.96391296	  Windows Kernel HTTP Library	
00000010	159.96391296	  Comprehensive Test Suite	
00000011	159.96391296	========================================	
00000012	159.96391296	KDNS: Random seed initialized: 0x00002FAA	
00000013	159.96395874	KDNS: Cache initialized (size=32, TTL=300s)	
00000014	159.96395874	KDNS: Library initialized	
00000015	159.96395874	[KHTTP] Initialized	
00000016	159.96395874	[+] Library initialized	
00000017	159.96395874	 	
00000018	159.96395874	========================================	
00000019	159.96395874	  PROTOCOL TESTS	
00000020	159.96395874	========================================	
00000021	159.96395874	 	
00000022	159.96395874	[DNS] Resolving ya.ru...	
00000023	159.96395874	KDNS: Resolving 'ya.ru' (depth=0, len=5)	
00000024	159.96397400	KDNS: Built query for 'ya.ru' (ID=0x1616, len=23)	
00000025	159.96405029	KDNS: TDI bound to port 50001	
00000026	159.96421814	KDNS: Sent 23 bytes	
00000027	160.03436279	KDNS: Received 86 bytes	
00000028	160.14065552	KDNS: Parsing 3 answer(s)	
00000029	160.14067078	KDNS: Found A record: 77.88.44.242	
00000030	160.14067078	KDNS: Resolution complete: ya.ru -> 77.88.44.242	
00000031	160.14067078	[DNS] Resolved to: 77.88.44.242	
00000032	160.14067078	[+] DNS Resolution - SUCCESS 	
00000033	160.14067078	 	
00000034	160.14067078	[TLS] Connecting to 192.168.56.1:4443...	
00000035	160.24961853	[TLS] Handshake completed	
00000036	160.25009155	[TLS] Sent 57 bytes	
00000037	160.25010681	[TLS] Received 76 bytes:	
00000038	160.25010681	[TLS-Server] Echo: GET / HTTP/1.1 	
00000039	160.25010681	Host: 192.168.56.1 	
00000040	160.25010681	Connection: close 	
00000041	160.25010681	 	
00000042	160.25010681	 	
00000043	160.25010681	[+] TLS Communication - SUCCESS 	
00000044	160.25076294	 	
00000045	160.25076294	[DTLS] Connecting to 192.168.56.1:4443...	
00000046	160.25840759	[DTLS] Handshake completed	
00000047	160.25860596	[DTLS] Sent 10 bytes	
00000048	160.45980835	[DTLS] Received 30 bytes:	
00000049	160.45982361	[DTLS-Server] Echo: Hello DTLS 	
00000050	160.45982361	[+] DTLS Communication - SUCCESS 	
00000051	160.46017456	 	
00000052	160.46017456	========================================	
00000053	160.46017456	  HTTP TESTS (Plain TCP)	
00000054	160.46017456	========================================	
00000055	160.46018982	 	
00000056	160.46018982	[HTTP GET] httpbin.org/get	
00000057	160.46018982	[KHTTP] Connecting to httpbin.org:80 (HTTPS: 0)	
00000058	160.46018982	KDNS: Cache miss, querying DNS	
00000059	160.46020508	KDNS: Resolving 'httpbin.org' (depth=0, len=11)	
00000060	160.46022034	KDNS: Built query for 'httpbin.org' (ID=0xEE2F, len=29)	
00000061	160.46063232	KDNS: TDI bound to port 50002	
00000062	160.46105957	KDNS: Sent 29 bytes	
00000063	160.52676392	KDNS: Received 191 bytes	
00000064	160.64273071	KDNS: Parsing 6 answer(s)	
00000065	160.64274597	KDNS: Found A record: 44.195.71.76	
00000066	160.64274597	KDNS: Resolution complete: httpbin.org -> 44.195.71.76	
00000067	160.64274597	KDNS: Cached [httpbin.org -> 44.195.71.76]	
00000068	160.64978027	[KHTTP] GET /get (Host: httpbin.org:80, HTTPS: 0)	
00000069	160.65014648	[KHTTP] Receiving response (max 1048576 bytes)...	
00000070	161.31587219	[KHTTP] Received 422 bytes (total: 422)	
00000071	162.40141296	[KHTTP] Connection closed, total received: 422 bytes	
00000072	162.40182495	[+] HTTP GET - SUCCESS (Status: 200, Body: 197 bytes) 	
00000073	162.40187073	 	
00000074	162.40187073	[HTTP POST] httpbin.org/post	
00000075	162.40188599	[KHTTP] Connecting to httpbin.org:80 (HTTPS: 0)	
00000076	162.40188599	KDNS: Cache HIT [httpbin.org -> 44.195.71.76]	
00000077	162.40817261	[KHTTP] POST /post (Host: httpbin.org:80, HTTPS: 0)	
00000078	162.40844727	[KHTTP] Receiving response (max 1048576 bytes)...	
00000079	162.95016479	[KHTTP] Received 632 bytes (total: 632)	
00000080	163.94595337	[KHTTP] Connection closed, total received: 632 bytes	
00000081	163.94674683	[+] HTTP POST - SUCCESS (Status: 200) 	
00000082	163.94674683	 	
00000083	163.94674683	[HTTP HEAD] ya.ru	
00000084	163.94676208	[KHTTP] Connecting to ya.ru:80 (HTTPS: 0)	
00000085	163.94676208	KDNS: Cache miss, querying DNS	
00000086	163.94676208	KDNS: Resolving 'ya.ru' (depth=0, len=5)	
00000087	163.94689941	KDNS: Built query for 'ya.ru' (ID=0x1028, len=23)	
00000088	163.94711304	KDNS: TDI bound to port 50003	
00000089	163.94783020	KDNS: Sent 23 bytes	
00000090	163.95918274	KDNS: Received 86 bytes	
00000091	164.06896973	KDNS: Parsing 3 answer(s)	
00000092	164.06896973	KDNS: Found A record: 77.88.44.242	
00000093	164.06896973	KDNS: Resolution complete: ya.ru -> 77.88.44.242	
00000094	164.06896973	KDNS: Cached [ya.ru -> 77.88.44.242]	
00000095	164.07963562	[KHTTP] HEAD / (Host: ya.ru:80, HTTPS: 0)	
00000096	164.07986450	[KHTTP] Receiving response (max 1048576 bytes)...	
00000097	164.12257385	[KHTTP] Received 1332 bytes (total: 1332)	
00000098	164.12260437	[KHTTP] Connection closed, total received: 1332 bytes	
00000099	164.12353516	[+] HTTP HEAD - SUCCESS (Status: 301, Body: 0 bytes) 	
00000100	164.12353516	 	
00000101	164.12353516	[REST] GET /posts/1	
00000102	164.12355042	[KHTTP] Connecting to jsonplaceholder.typicode.com:80 (HTTPS: 0)	
00000103	164.12355042	KDNS: Cache miss, querying DNS	
00000104	164.12355042	KDNS: Resolving 'jsonplaceholder.typicode.com' (depth=0, len=28)	
00000105	164.12356567	KDNS: Built query for 'jsonplaceholder.typicode.com' (ID=0x1809, len=46)	
00000106	164.12365723	KDNS: TDI bound to port 50004	
00000107	164.12387085	KDNS: Sent 46 bytes	
00000108	164.19253540	KDNS: Received 134 bytes	
00000109	164.29376221	KDNS: Parsing 2 answer(s)	
00000110	164.29376221	KDNS: Found A record: 188.114.96.0	
00000111	164.29377747	KDNS: Resolution complete: jsonplaceholder.typicode.com -> 188.114.96.0	
00000112	164.29377747	KDNS: Cached [jsonplaceholder.typicode.com -> 188.114.96.0]	
00000113	164.30636597	[KHTTP] GET /posts/1 (Host: jsonplaceholder.typicode.com:80, HTTPS: 0)	
00000114	164.30715942	[KHTTP] Receiving response (max 1048576 bytes)...	
00000115	164.50921631	[KHTTP] Received 1479 bytes (total: 1479)	
00000116	165.49783325	[KHTTP] Connection closed, total received: 1479 bytes	
00000117	165.49855042	[+] REST GET - SUCCESS (Status: 200) 	
00000118	165.49855042	 	
00000119	165.49855042	[REST] POST /posts	
00000120	165.49856567	[KHTTP] Connecting to jsonplaceholder.typicode.com:80 (HTTPS: 0)	
00000121	165.49856567	KDNS: Cache HIT [jsonplaceholder.typicode.com -> 188.114.96.0]	
00000122	165.50584412	[KHTTP] POST /posts (Host: jsonplaceholder.typicode.com:80, HTTPS: 0)	
00000123	165.50640869	[KHTTP] Receiving response (max 1048576 bytes)...	
00000124	165.87037659	[KHTTP] Received 1366 bytes (total: 1366)	
00000125	166.86279297	[KHTTP] Connection closed, total received: 1366 bytes	
00000126	166.86315918	[+] REST POST - SUCCESS (Status: 201) 	
00000127	166.86315918	 	
00000128	166.86315918	[REST] PUT /posts/1	
00000129	166.86315918	[KHTTP] Connecting to jsonplaceholder.typicode.com:80 (HTTPS: 0)	
00000130	166.86315918	KDNS: Cache HIT [jsonplaceholder.typicode.com -> 188.114.96.0]	
00000131	166.87074280	[KHTTP] PUT /posts/1 (Host: jsonplaceholder.typicode.com:80, HTTPS: 0)	
00000132	166.87101746	[KHTTP] Receiving response (max 1048576 bytes)...	
00000133	167.23841858	[KHTTP] Received 1229 bytes (total: 1229)	
00000134	168.23306274	[KHTTP] Connection closed, total received: 1229 bytes	
00000135	168.23329163	[+] REST PUT - SUCCESS (Status: 200) 	
00000136	168.23329163	 	
00000137	168.23329163	[REST] PATCH /posts/1	
00000138	168.23329163	[KHTTP] Connecting to jsonplaceholder.typicode.com:80 (HTTPS: 0)	
00000139	168.23329163	KDNS: Cache HIT [jsonplaceholder.typicode.com -> 188.114.96.0]	
00000140	168.24009705	[KHTTP] PATCH /posts/1 (Host: jsonplaceholder.typicode.com:80, HTTPS: 0)	
00000141	168.24032593	[KHTTP] Receiving response (max 1048576 bytes)...	
00000142	168.60278320	[KHTTP] Received 1379 bytes (total: 1379)	
00000143	169.59378052	[KHTTP] Connection closed, total received: 1379 bytes	
00000144	169.59402466	[+] REST PATCH - SUCCESS (Status: 200) 	
00000145	169.59403992	 	
00000146	169.59403992	[REST] DELETE /posts/1	
00000147	169.59403992	[KHTTP] Connecting to jsonplaceholder.typicode.com:80 (HTTPS: 0)	
00000148	169.59403992	KDNS: Cache HIT [jsonplaceholder.typicode.com -> 188.114.96.0]	
00000149	169.60183716	[KHTTP] DELETE /posts/1 (Host: jsonplaceholder.typicode.com:80, HTTPS: 0)	
00000150	169.60221863	[KHTTP] Receiving response (max 1048576 bytes)...	
00000151	169.95625305	[KHTTP] Received 1157 bytes (total: 1157)	
00000152	170.95117188	[KHTTP] Connection closed, total received: 1157 bytes	
00000153	170.95173645	[+] REST DELETE - SUCCESS (Status: 200) 	
00000154	170.95173645	 	
00000155	170.95173645	========================================	
00000156	170.95173645	  HTTPS TESTS (TLS)	
00000157	170.95173645	========================================	
00000158	170.95173645	 	
00000159	170.95173645	[HTTPS GET] httpbin.org/get	
00000160	170.95175171	[KHTTP] Connecting to httpbin.org:443 (HTTPS: 1)	
00000161	170.95175171	KDNS: Cache HIT [httpbin.org -> 44.195.71.76]	
00000162	171.46496582	[KHTTP] GET /get (Host: httpbin.org:443, HTTPS: 1)	
00000163	171.46520996	[KHTTP] Receiving response (max 1048576 bytes)...	
00000164	171.61592102	[KHTTP] Received 458 bytes (total: 458)	
00000165	171.61596680	[KHTTP] Connection closed, total received: 458 bytes	
00000166	171.61734009	[+] HTTPS GET - SUCCESS (Status: 200, Body: 233 bytes) 	
00000167	171.61735535	[Preview] {	
00000168	171.61735535	  "args": {}, 	
00000169	171.61735535	  "headers": {	
00000170	171.61735535	    "Accept": "application/json", 	
00000171	171.61735535	    "Host": "httpbin.org", 	
00000172	171.61735535	    "X-Amzn-Trace-Id": "Root=1-69901c2d-1c1c4fa11ad357f...	
00000173	171.61735535	 	
00000174	171.61735535	[HTTPS POST] httpbin.org/post	
00000175	171.61737061	[KHTTP] Connecting to httpbin.org:443 (HTTPS: 1)	
00000176	171.61737061	KDNS: Cache HIT [httpbin.org -> 44.195.71.76]	
00000177	172.12850952	[KHTTP] POST /post (Host: httpbin.org:443, HTTPS: 1)	
00000178	172.12893677	[KHTTP] Receiving response (max 1048576 bytes)...	
00000179	172.28584290	[KHTTP] Received 225 bytes (total: 225)	
00000180	172.28584290	[KHTTP] Received 447 bytes (total: 672)	
00000181	173.28433228	[KHTTP] Connection closed, total received: 672 bytes	
00000182	173.28503418	[+] HTTPS POST - SUCCESS (Status: 200) 	
00000183	173.28503418	 	
00000184	173.28503418	[HTTPS GET] jsonplaceholder.typicode.com/posts/1	
00000185	173.28503418	[KHTTP] Connecting to jsonplaceholder.typicode.com:443 (HTTPS: 1)	
00000186	173.28504944	KDNS: Cache HIT [jsonplaceholder.typicode.com -> 188.114.96.0]	
00000187	173.54335022	[KHTTP] GET /posts/1 (Host: jsonplaceholder.typicode.com:443, HTTPS: 1)	
00000188	173.54411316	[KHTTP] Receiving response (max 1048576 bytes)...	
00000189	173.61203003	[KHTTP] Received 1369 bytes (total: 1369)	
00000190	173.61207581	[KHTTP] Received 137 bytes (total: 1506)	
00000191	173.61209106	[KHTTP] Connection closed, total received: 1506 bytes	
00000192	173.61331177	[+] HTTPS REST API - SUCCESS (Status: 200) 	
00000193	173.61332703	[Preview] {	
00000194	173.61332703	  "userId": 1,	
00000195	173.61332703	  "id": 1,	
00000196	173.61332703	  "title": "sunt aut facere repellat provident occaecati excepturi optio...	
00000197	173.61332703	 	
00000198	173.61332703	[HTTPS HEAD] ya.ru	
00000199	173.61334229	[KHTTP] Connecting to ya.ru:443 (HTTPS: 1)	
00000200	173.61334229	KDNS: Cache HIT [ya.ru -> 77.88.44.242]	
00000201	173.70417786	[KHTTP] HEAD / (Host: ya.ru:443, HTTPS: 1)	
00000202	173.70503235	[KHTTP] Receiving response (max 1048576 bytes)...	
00000203	173.73971558	[KHTTP] Received 1717 bytes (total: 1717)	
00000204	173.73974609	[KHTTP] Connection closed, total received: 1717 bytes	
00000205	173.74084473	[+] HTTPS HEAD - SUCCESS (Status: 200) 	
00000206	173.74084473	 	
00000207	173.74084473	[REST-HTTPS] GET /posts/1	
00000208	173.74085999	[KHTTP] Connecting to jsonplaceholder.typicode.com:443 (HTTPS: 1)	
00000209	173.74085999	KDNS: Cache HIT [jsonplaceholder.typicode.com -> 188.114.96.0]	
00000210	174.07218933	[KHTTP] GET /posts/1 (Host: jsonplaceholder.typicode.com:443, HTTPS: 1)	
00000211	174.07334900	[KHTTP] Receiving response (max 1048576 bytes)...	
00000212	174.15133667	[KHTTP] Received 1369 bytes (total: 1369)	
00000213	174.15136719	[KHTTP] Received 137 bytes (total: 1506)	
00000214	174.15141296	[KHTTP] Connection closed, total received: 1506 bytes	
00000215	174.15275574	[+] REST-HTTPS GET - SUCCESS (Status: 200) 	
00000216	174.15275574	 	
00000217	174.15275574	[REST-HTTPS] POST /posts	
00000218	174.15277100	[KHTTP] Connecting to jsonplaceholder.typicode.com:443 (HTTPS: 1)	
00000219	174.15277100	KDNS: Cache HIT [jsonplaceholder.typicode.com -> 188.114.96.0]	
00000220	174.42068481	[KHTTP] POST /posts (Host: jsonplaceholder.typicode.com:443, HTTPS: 1)	
00000221	174.42143250	[KHTTP] Receiving response (max 1048576 bytes)...	
00000222	174.57949829	[KHTTP] Received 1369 bytes (total: 1369)	
00000223	174.57952881	[KHTTP] Received 23 bytes (total: 1392)	
00000224	174.57955933	[KHTTP] Connection closed, total received: 1392 bytes	
00000225	174.58045959	[+] REST-HTTPS POST - SUCCESS (Status: 201) 	
00000226	174.58045959	 	
00000227	174.58045959	[REST-HTTPS] PUT /posts/1	
00000228	174.58045959	[KHTTP] Connecting to jsonplaceholder.typicode.com:443 (HTTPS: 1)	
00000229	174.58045959	KDNS: Cache HIT [jsonplaceholder.typicode.com -> 188.114.96.0]	
00000230	174.84005737	[KHTTP] PUT /posts/1 (Host: jsonplaceholder.typicode.com:443, HTTPS: 1)	
00000231	174.84060669	[KHTTP] Receiving response (max 1048576 bytes)...	
00000232	175.16284180	[KHTTP] Received 1274 bytes (total: 1274)	
00000233	175.16288757	[KHTTP] Connection closed, total received: 1274 bytes	
00000234	175.16415405	[+] REST-HTTPS PUT - SUCCESS (Status: 200) 	
00000235	175.16415405	 	
00000236	175.16415405	[REST-HTTPS] DELETE /posts/1	
00000237	175.16415405	[KHTTP] Connecting to jsonplaceholder.typicode.com:443 (HTTPS: 1)	
00000238	175.16424561	KDNS: Cache HIT [jsonplaceholder.typicode.com -> 188.114.96.0]	
00000239	175.42413330	[KHTTP] DELETE /posts/1 (Host: jsonplaceholder.typicode.com:443, HTTPS: 1)	
00000240	175.42521667	[KHTTP] Receiving response (max 1048576 bytes)...	
00000241	175.74922180	[KHTTP] Received 1191 bytes (total: 1191)	
00000242	175.74925232	[KHTTP] Connection closed, total received: 1191 bytes	
00000243	175.75065613	[+] REST-HTTPS DELETE - SUCCESS (Status: 200) 	
00000244	175.75065613	 	
00000245	175.75065613	========================================	
00000246	175.75065613	  FILE UPLOAD TESTS	
00000247	175.75065613	========================================	
00000248	175.75065613	 	
00000249	175.75065613	[UPLOAD] Single file test (1KB)	
00000250	175.75067139	[KHTTP] Starting multipart request to https://httpbin.org/post (chunked: 0, streaming: 0)	
00000251	175.75067139	[KHTTP] Generated boundary: ----gm2Ric3E4nJa0I5SOS1v7GF3zJFV30MB1aumjtII	
00000252	175.75068665	[KHTTP] Connecting to httpbin.org:443 (HTTPS: 1)	
00000253	175.75068665	KDNS: Cache HIT [httpbin.org -> 44.195.71.76]	
00000254	176.27429199	[KHTTP] POST /post (Host: httpbin.org:443, HTTPS: 1)	
00000255	176.27430725	[KHTTP] Built multipart body: 1236 bytes	
00000256	176.27430725	[KHTTP] Built multipart body: 1236 bytes	
00000257	176.27468872	[KHTTP] Headers sent: 1441 bytes	
00000258	176.27522278	[KHTTP] Receiving response (max 1048576 bytes)...	
00000259	176.43721008	[KHTTP] Received 2086 bytes (total: 2086)	
00000260	177.43667603	[KHTTP] Connection closed, total received: 2086 bytes	
00000261	177.43678284	[KHTTP] Response received: status 200	
00000262	177.43707275	[+] Single File Upload - SUCCESS (Status: 200, Response: 1860 bytes) 	
00000263	179.43757629	 	
00000264	179.43757629	[UPLOAD] File with form fields (2KB)	
00000265	179.43760681	[KHTTP] Starting multipart request to https://example.com/upload (chunked: 0, streaming: 0)	
00000266	179.43763733	[KHTTP] Generated boundary: ----esepwFauIDvzfnVtFK0coDOBkmQXwqe85wUA3bu3	
00000267	179.43765259	[KHTTP] Connecting to example.com:443 (HTTPS: 1)	
00000268	179.43765259	KDNS: Cache miss, querying DNS	
00000269	179.43766785	KDNS: Resolving 'example.com' (depth=0, len=11)	
00000270	179.43766785	KDNS: Built query for 'example.com' (ID=0x2307, len=29)	
00000271	179.43786621	KDNS: TDI bound to port 50005	
00000272	179.43820190	KDNS: Sent 29 bytes	
00000273	179.50164795	KDNS: Received 83 bytes	
00000274	179.61399841	KDNS: Parsing 2 answer(s)	
00000275	179.61401367	KDNS: Found A record: 104.18.27.120	
00000276	179.61402893	KDNS: Resolution complete: example.com -> 104.18.27.120	
00000277	179.61402893	KDNS: Cached [example.com -> 104.18.27.120]	
00000278	180.51324463	[KHTTP] POST /upload (Host: example.com:443, HTTPS: 1)	
00000279	180.51325989	[KHTTP] Built multipart body: 2494 bytes	
00000280	180.51325989	[KHTTP] Built multipart body: 2494 bytes	
00000281	180.51406860	[KHTTP] Headers sent: 2669 bytes	
00000282	180.51518250	[KHTTP] Receiving response (max 1048576 bytes)...	
00000283	180.58204651	[KHTTP] Received 706 bytes (total: 706)	
00000284	180.58206177	[KHTTP] Received 5 bytes (total: 711)	
00000285	180.58206177	[KHTTP] Connection closed, total received: 711 bytes	
00000286	180.58218384	[KHTTP] Response received: status 405	
00000287	180.58255005	[+] File+Form Upload - SUCCESS (Status: 405) 	
00000288	182.59306335	 	
00000289	182.59306335	[UPLOAD] Multiple files with progress (512B + 1KB)	
00000290	182.59306335	[KHTTP] Starting multipart request to https://httpbin.org/post (chunked: 0, streaming: 0)	
00000291	182.59307861	[KHTTP] Generated boundary: ----vll8jNMyKGWLElEc4i3jN5qzmpNYxPGIA33c18u6	
00000292	182.59309387	[KHTTP] Connecting to httpbin.org:443 (HTTPS: 1)	
00000293	182.59309387	KDNS: Cache HIT [httpbin.org -> 44.195.71.76]	
00000294	183.11798096	[KHTTP] POST /post (Host: httpbin.org:443, HTTPS: 1)	
00000295	183.11799622	[KHTTP] Built multipart body: 1900 bytes	
00000296	183.11799622	[KHTTP] Built multipart body: 1900 bytes	
00000297	183.11828613	[KHTTP] Headers sent: 2073 bytes	
00000298	183.11909485	[KHTTP] Receiving response (max 5242880 bytes)...	
00000299	183.28242493	[KHTTP] Connection closed, total received: 0 bytes	
00000300	183.28244019	[KHTTP] [WARN] No data received	
00000301	183.28321838	[-] Multiple Files Upload - FAILED (0x80000022) - Upload failed 	
00000302	185.29963684	 	
00000303	185.29963684	[UPLOAD] Large file chunked transfer (5MB)	
00000304	185.30018616	[KHTTP] Large body detected (5242880 bytes), enabling chunked transfer	
00000305	185.30018616	[KHTTP] Starting multipart request to http://192.168.56.1:8080/upload (chunked: 1, streaming: 0)	
00000306	185.30020142	[KHTTP] Generated boundary: ----GQX2qZAtoAcRR9aMpf4ws6GqN2Gn7JEoKdKnIK1i	
00000307	185.30020142	[KHTTP] Connecting to 192.168.56.1:8080 (HTTPS: 0)	
00000308	185.30020142	KDNS: Cache miss, querying DNS	
00000309	185.30020142	KDNS: Resolving '192.168.56.1' (depth=0, len=12)	
00000310	185.30021667	KDNS: Parsed IPv4: 192.168.56.1 -> 0x0138A8C0	
00000311	185.30021667	KDNS: Hostname is IP address, no DNS query needed	
00000312	185.30021667	KDNS: Cached [192.168.56.1 -> 192.168.56.1]	
00000313	185.30067444	[KHTTP] POST /upload (Host: 192.168.56.1:8080, HTTPS: 0)	
00000314	185.30186462	[KHTTP] Built multipart body: 5243097 bytes	
00000315	185.30186462	[KHTTP] Built multipart body: 5243097 bytes	
00000316	185.34741211	[KHTTP] Headers sent: 182 bytes	
00000317	195.60365295	[KHTTP] [STREAMING] Sending chunk terminator	
00000318	195.60842896	[KHTTP] Receiving response (max 5242880 bytes)...	
00000319	195.60852051	[KHTTP] Received 266 bytes (total: 266)	
00000320	195.60853577	[KHTTP] Connection closed, total received: 266 bytes	
00000321	195.60856628	[KHTTP] Response received: status 200	
00000322	195.61056519	[+] Large File Upload - SUCCESS (Status: 200, Size: 5242880 bytes) 	
00000323	197.62463379	 	
00000324	197.62463379	[UPLOAD] Streaming file from disk	
00000325	197.62464905	[KHTTP] Starting multipart request to https://192.168.56.1:8443/upload (chunked: 1, streaming: 1)	
00000326	197.62469482	[KHTTP] Generated boundary: ----p1IO15zmjbs9BXkvSDKeJITm4YCBOeg7g20ZNiQ9	
00000327	197.62471008	[KHTTP] Connecting to 192.168.56.1:8443 (HTTPS: 1)	
00000328	197.62472534	KDNS: Cache HIT [192.168.56.1 -> 192.168.56.1]	
00000329	197.73049927	[KHTTP] POST /upload (Host: 192.168.56.1:8443, HTTPS: 1)	
00000330	197.73049927	[KHTTP] Using streaming mode	
00000331	197.77610779	[KHTTP] Headers sent: 182 bytes	
00000332	197.91996765	[KHTTP] [STREAMING] File size: 5193152 bytes	
00000333	198.02517700	[PROGRESS] 5% (262305/5193152 bytes)	
00000334	198.14799500	[PROGRESS] 10% (524449/5193152 bytes)	
00000335	198.25787354	[PROGRESS] 15% (786593/5193152 bytes)	
00000336	198.36595154	[PROGRESS] 20% (1048737/5193152 bytes)	
00000337	198.47526550	[PROGRESS] 25% (1310881/5193152 bytes)	
00000338	198.58503723	[PROGRESS] 30% (1573025/5193152 bytes)	
00000339	198.69438171	[PROGRESS] 35% (1835169/5193152 bytes)	
00000340	198.80296326	[PROGRESS] 40% (2097313/5193152 bytes)	
00000341	198.91279602	[PROGRESS] 45% (2359457/5193152 bytes)	
00000342	199.02342224	[PROGRESS] 50% (2621601/5193152 bytes)	
00000343	199.13314819	[PROGRESS] 55% (2883745/5193152 bytes)	
00000344	199.24330139	[PROGRESS] 60% (3145889/5193152 bytes)	
00000345	199.35269165	[PROGRESS] 65% (3408033/5193152 bytes)	
00000346	199.46215820	[PROGRESS] 70% (3670177/5193152 bytes)	
00000347	199.57136536	[PROGRESS] 75% (3932321/5193152 bytes)	
00000348	199.66432190	[PROGRESS] 80% (4194465/5193152 bytes)	
00000349	199.77191162	[PROGRESS] 85% (4456609/5193152 bytes)	
00000350	199.88069153	[PROGRESS] 90% (4718753/5193152 bytes)	
00000351	199.98844910	[PROGRESS] 95% (4980897/5193152 bytes)	
00000352	200.09631348	[PROGRESS] 100% (5193313/5193152 bytes)	
00000353	200.09631348	[KHTTP] Upload progress: 100%	
00000354	200.23730469	[PROGRESS] 100% (5193315/5193152 bytes)	
00000355	200.23730469	[KHTTP] Upload progress: 100%	
00000356	200.37600708	[PROGRESS] 100% (5193365/5193152 bytes)	
00000357	200.37600708	[KHTTP] Upload progress: 100%	
00000358	200.37602234	[KHTTP] [STREAMING] Sending chunk terminator	
00000359	200.37727356	[KHTTP] Receiving response (max 0 bytes)...	
00000360	200.37731934	[KHTTP] Received 265 bytes (total: 265)	
00000361	200.37734985	[KHTTP] Connection closed, total received: 265 bytes	
00000362	200.37738037	[KHTTP] Response received: status 200	
00000363	200.37802124	[+] Streaming Upload - SUCCESS (Status: 200) 	
00000364	200.37802124	 	
00000365	200.37803650	========================================	
00000366	200.37803650	  All Tests Completed	
00000367	200.37803650	========================================	
00000368	204.42848206	 	
00000369	204.42848206	========================================	
00000370	204.42849731	  Unloading Driver	
00000371	204.42849731	========================================	
00000372	204.42849731	KDNS: Cache cleanup (hits=16, misses=5, evictions=0)	
00000373	204.42849731	KDNS: Library cleanup complete	
00000374	204.42849731	[KHTTP] Cleaned up	
00000375	204.42849731	[+] Driver unloaded successfully	
```

```log
  Multi-Protocol Server Started:
[TLS] Listening TCP/4443...
[HTTP] Listening on 0.0.0.0:8080...
[DTLS] Listening UDP/4443...
[HTTPS] Listening on 0.0.0.0:8443...
   ├─ TLS/DTLS: 0.0.0.0:4443 (TCP & UDP)
   ├─ HTTP:     http://0.0.0.0:8080
   └─ HTTPS:    https://0.0.0.0:8443
  Test endpoints:
   POST http://localhost:8080/upload     (chunked multipart)
   POST https://localhost:8443/upload    (chunked multipart)
   POST http://localhost:8080/echo       (echo test)
[TLS] New connection from 192.168.56.7:65334
[TLS] RECV (192.168.56.7:65334): GET / HTTP/1.1
    Host: 192.168.56.1
    Connection: close
[TLS] Connection closed (192.168.56.7:65334): EOF
[DTLS] New connection from 192.168.56.7:62083
[DTLS] RECV (192.168.56.7:62083): Hello DTLS
[DTLS] Connection closed (192.168.56.7:62083): EOF
[UPLOAD] POST /upload from 192.168.56.7:65354
[UPLOAD] Content-Type: multipart/form-data; boundary=----GQX2qZAtoAcRR9aMpf4ws6GqN2Gn7JEoKdKnIK1i
[UPLOAD] Transfer-Encoding:
[UPLOAD] Content-Length:
[UPLOAD] Is Chunked: false
[UPLOAD] Progress: 0 MB (100 chunks)
[UPLOAD] Progress: 1 MB (128 chunks)
[UPLOAD] Progress: 1 MB (200 chunks)
[UPLOAD] Progress: 2 MB (256 chunks)
[UPLOAD] Progress: 2 MB (300 chunks)
[UPLOAD] Progress: 3 MB (384 chunks)
[UPLOAD] Progress: 3 MB (400 chunks)
[UPLOAD] Progress: 3 MB (500 chunks)
[UPLOAD] Progress: 4 MB (512 chunks)
[UPLOAD] Progress: 4 MB (600 chunks)
[UPLOAD] Progress: 5 MB (640 chunks)
[UPLOAD]   Complete: 5243097 bytes (641 chunks) in 10.30s (0.49 MB/s)
[UPLOAD] POST /upload from 192.168.56.7:65355
[UPLOAD] Content-Type: multipart/form-data; boundary=----p1IO15zmjbs9BXkvSDKeJITm4YCBOeg7g20ZNiQ9
[UPLOAD] Transfer-Encoding:
[UPLOAD] Content-Length:
[UPLOAD] Is Chunked: false
[UPLOAD] Progress: 0 MB (100 chunks)
[UPLOAD] Progress: 1 MB (200 chunks)
[UPLOAD] Progress: 2 MB (300 chunks)
[UPLOAD] Progress: 3 MB (400 chunks)
[UPLOAD] Progress: 3 MB (500 chunks)
[UPLOAD] Progress: 4 MB (600 chunks)
[UPLOAD]   Complete: 5193365 bytes (637 chunks) in 2.64s (1.87 MB/s)
```