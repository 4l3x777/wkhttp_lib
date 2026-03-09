```log
00000001	0.00000000	 	
00000002	0.00000040	========================================	
00000003	0.00000330	  Windows Kernel HTTP Library	
00000004	0.00000410	  Comprehensive Test Suite	
00000005	0.00000500	========================================	
00000006	0.00000650	KDNS: Random seed initialized: 0x00076AA7	
00000007	0.00003170	KDNS: Cache initialized (size=32, TTL=300s)	
00000008	0.00003270	KDNS: Library initialized	
00000009	0.00003350	[KHTTP] Initialized	
00000010	0.00003420	[+] Library initialized	
00000011	0.00003490	 	
00000012	0.00003510	========================================	
00000013	0.00003600	  PROTOCOL TESTS	
00000014	0.00003680	========================================	
00000015	0.00003750	 	
00000016	0.00003760	[DNS] Resolving ya.ru...	
00000017	0.00003860	KDNS: Resolving 'ya.ru' (depth=0, len=5)	
00000018	0.00013260	KDNS: Built query for 'ya.ru' (ID=0x29D1, len=23)	
00000019	0.00019820	KDNS: TDI bound to port 50001	
00000020	0.00039840	KDNS: Sent 23 bytes	
00000021	0.06478920	KDNS: Received 86 bytes	
00000022	0.16943350	KDNS: Parsing 3 answer(s)	
00000023	0.16943920	KDNS: Found A record: 5.255.255.242	
00000024	0.16944340	KDNS: Resolution complete: ya.ru -> 5.255.255.242	
00000025	0.16944540	[DNS] Resolved to: 5.255.255.242	
00000026	0.16944860	[+] DNS Resolution - SUCCESS 	
00000027	0.16945019	 	
00000028	0.16945040	[TLS] Connecting to 192.168.56.1:4443...	
00000029	0.27186331	[TLS] Handshake completed	
00000030	0.27228409	[TLS] Sent 57 bytes	
00000031	0.27234310	[TLS] Received 76 bytes:	
00000032	0.27234471	[TLS-Server] Echo: GET / HTTP/1.1 	
00000033	0.27234489	Host: 192.168.56.1 	
00000034	0.27234501	Connection: close 	
00000035	0.27234510	 	
00000036	0.27234599	 	
00000037	0.27234781	[+] TLS Communication - SUCCESS 	
00000038	0.27275789	 	
00000039	0.27275819	[DTLS] Connecting to 192.168.56.1:4443...	
00000040	0.27954939	[DTLS] Handshake completed	
00000041	0.27963391	[DTLS] Sent 10 bytes	
00000042	0.48118761	[DTLS] Received 30 bytes:	
00000043	0.48120451	[DTLS-Server] Echo: Hello DTLS 	
00000044	0.48121241	[+] DTLS Communication - SUCCESS 	
00000045	0.48176581	 	
00000046	0.48176691	========================================	
00000047	0.48177421	  HTTP TESTS (Plain TCP)	
00000048	0.48177800	========================================	
00000049	0.48178160	 	
00000050	0.48178199	[HTTP GET] httpbin.org/get	
00000051	0.48179021	[KHTTP] Connecting to httpbin.org:80 (HTTPS: 0)	
00000052	0.48179600	KDNS: Cache miss, querying DNS	
00000053	0.48180100	KDNS: Resolving 'httpbin.org' (depth=0, len=11)	
00000054	0.48181131	KDNS: Built query for 'httpbin.org' (ID=0x58BD, len=29)	
00000055	0.48201311	KDNS: TDI bound to port 50002	
00000056	0.48266149	KDNS: Sent 29 bytes	
00000057	0.55742580	KDNS: Received 191 bytes	
00000058	0.66517669	KDNS: Parsing 6 answer(s)	
00000059	0.66518080	KDNS: Found A record: 34.199.144.244	
00000060	0.66518348	KDNS: Resolution complete: httpbin.org -> 34.199.144.244	
00000061	0.66518539	KDNS: Cached [httpbin.org -> 34.199.144.244]	
00000062	0.71880192	[KHTTP] GET /get (Host: httpbin.org:80, HTTPS: 0)	
00000063	0.71934909	[KHTTP] Receiving response (max 1048576 bytes)...	
00000064	1.08089530	[KHTTP] Received 422 bytes (total: 422)	
00000065	2.07175636	[KHTTP] Connection closed, total received: 422 bytes	
00000066	2.07207680	[+] HTTP GET - SUCCESS (Status: 200, Body: 197 bytes) 	
00000067	2.07207870	 	
00000068	2.07207918	[HTTP POST] httpbin.org/post	
00000069	2.07208419	[KHTTP] Connecting to httpbin.org:80 (HTTPS: 0)	
00000070	2.07208705	KDNS: Cache HIT [httpbin.org -> 34.199.144.244]	
00000071	2.07868290	[KHTTP] POST /post (Host: httpbin.org:80, HTTPS: 0)	
00000072	2.07913327	[KHTTP] Receiving response (max 1048576 bytes)...	
00000073	2.44077802	[KHTTP] Received 632 bytes (total: 632)	
00000074	3.43417645	[KHTTP] Connection closed, total received: 632 bytes	
00000075	3.43437195	[+] HTTP POST - SUCCESS (Status: 200) 	
00000076	3.43437290	 	
00000077	3.43437314	[HTTP HEAD] ya.ru	
00000078	3.43437600	[KHTTP] Connecting to ya.ru:80 (HTTPS: 0)	
00000079	3.43437767	KDNS: Cache miss, querying DNS	
00000080	3.43437886	KDNS: Resolving 'ya.ru' (depth=0, len=5)	
00000081	3.43438411	KDNS: Built query for 'ya.ru' (ID=0xB220, len=23)	
00000082	3.43448520	KDNS: TDI bound to port 50003	
00000083	3.43457389	KDNS: Sent 23 bytes	
00000084	3.44296050	KDNS: Received 86 bytes	
00000085	3.55140567	KDNS: Parsing 3 answer(s)	
00000086	3.55140924	KDNS: Found A record: 5.255.255.242	
00000087	3.55141163	KDNS: Resolution complete: ya.ru -> 5.255.255.242	
00000088	3.55141282	KDNS: Cached [ya.ru -> 5.255.255.242]	
00000089	3.55933189	[KHTTP] HEAD / (Host: ya.ru:80, HTTPS: 0)	
00000090	3.55995131	[KHTTP] Receiving response (max 1048576 bytes)...	
00000091	3.64796233	[KHTTP] Received 1330 bytes (total: 1330)	
00000092	3.64797688	[KHTTP] Connection closed, total received: 1330 bytes	
00000093	3.64828086	[+] HTTP HEAD - SUCCESS (Status: 301, Body: 0 bytes) 	
00000094	3.64828205	 	
00000095	3.64828229	[REST] GET /posts/1	
00000096	3.64828444	[KHTTP] Connecting to jsonplaceholder.typicode.com:80 (HTTPS: 0)	
00000097	3.64828634	KDNS: Cache miss, querying DNS	
00000098	3.64828753	KDNS: Resolving 'jsonplaceholder.typicode.com' (depth=0, len=28)	
00000099	3.64829111	KDNS: Built query for 'jsonplaceholder.typicode.com' (ID=0x46B6, len=46)	
00000100	3.64836073	KDNS: TDI bound to port 50004	
00000101	3.64845395	KDNS: Sent 46 bytes	
00000102	3.71369410	KDNS: Received 134 bytes	
00000103	3.82713151	KDNS: Parsing 2 answer(s)	
00000104	3.82713604	KDNS: Found A record: 188.114.96.0	
00000105	3.82713914	KDNS: Resolution complete: jsonplaceholder.typicode.com -> 188.114.96.0	
00000106	3.82714152	KDNS: Cached [jsonplaceholder.typicode.com -> 188.114.96.0]	
00000107	3.83433843	[KHTTP] GET /posts/1 (Host: jsonplaceholder.typicode.com:80, HTTPS: 0)	
00000108	3.83463001	[KHTTP] Receiving response (max 1048576 bytes)...	
00000109	4.03575993	[KHTTP] Received 1476 bytes (total: 1476)	
00000110	5.03076887	[KHTTP] Connection closed, total received: 1476 bytes	
00000111	5.03122139	[+] REST GET - SUCCESS (Status: 200) 	
00000112	5.03122377	 	
00000113	5.03122377	[REST] POST /posts	
00000114	5.03122950	[KHTTP] Connecting to jsonplaceholder.typicode.com:80 (HTTPS: 0)	
00000115	5.03128099	KDNS: Cache HIT [jsonplaceholder.typicode.com -> 188.114.96.0]	
00000116	5.07331467	[KHTTP] POST /posts (Host: jsonplaceholder.typicode.com:80, HTTPS: 0)	
00000117	5.07360458	[KHTTP] Receiving response (max 1048576 bytes)...	
00000118	5.44569778	[KHTTP] Received 1354 bytes (total: 1354)	
00000119	6.45387983	[KHTTP] Connection closed, total received: 1354 bytes	
00000120	6.45466900	[+] REST POST - SUCCESS (Status: 201) 	
00000121	6.45467377	 	
00000122	6.45467424	[REST] PUT /posts/1	
00000123	6.45468569	[KHTTP] Connecting to jsonplaceholder.typicode.com:80 (HTTPS: 0)	
00000124	6.45469379	KDNS: Cache HIT [jsonplaceholder.typicode.com -> 188.114.96.0]	
00000125	6.46190643	[KHTTP] PUT /posts/1 (Host: jsonplaceholder.typicode.com:80, HTTPS: 0)	
00000126	6.46289349	[KHTTP] Receiving response (max 1048576 bytes)...	
00000127	6.82571602	[KHTTP] Received 1233 bytes (total: 1233)	
00000128	7.82111979	[KHTTP] Connection closed, total received: 1233 bytes	
00000129	7.82157850	[+] REST PUT - SUCCESS (Status: 200) 	
00000130	7.82158089	 	
00000131	7.82158136	[REST] PATCH /posts/1	
00000132	7.82158899	[KHTTP] Connecting to jsonplaceholder.typicode.com:80 (HTTPS: 0)	
00000133	7.82159376	KDNS: Cache HIT [jsonplaceholder.typicode.com -> 188.114.96.0]	
00000134	7.83028078	[KHTTP] PATCH /posts/1 (Host: jsonplaceholder.typicode.com:80, HTTPS: 0)	
00000135	7.83096886	[KHTTP] Receiving response (max 1048576 bytes)...	
00000136	8.20285416	[KHTTP] Received 1387 bytes (total: 1387)	
00000137	9.18453217	[KHTTP] Connection closed, total received: 1387 bytes	
00000138	9.18477345	[+] REST PATCH - SUCCESS (Status: 200) 	
00000139	9.18477440	 	
00000140	9.18477440	[REST] DELETE /posts/1	
00000141	9.18477821	[KHTTP] Connecting to jsonplaceholder.typicode.com:80 (HTTPS: 0)	
00000142	9.18478107	KDNS: Cache HIT [jsonplaceholder.typicode.com -> 188.114.96.0]	
00000143	9.19263744	[KHTTP] DELETE /posts/1 (Host: jsonplaceholder.typicode.com:80, HTTPS: 0)	
00000144	9.19301987	[KHTTP] Receiving response (max 1048576 bytes)...	
00000145	9.55419540	[KHTTP] Received 1153 bytes (total: 1153)	
00000146	10.54717636	[KHTTP] Connection closed, total received: 1153 bytes	
00000147	10.54794884	[+] REST DELETE - SUCCESS (Status: 200) 	
00000148	10.54795456	 	
00000149	10.54795551	========================================	
00000150	10.54796124	  HTTPS TESTS (TLS)	
00000151	10.54796505	========================================	
00000152	10.54796886	 	
00000153	10.54796982	[HTTPS GET] httpbin.org/get	
00000154	10.54797935	[KHTTP] Connecting to httpbin.org:443 (HTTPS: 1)	
00000155	10.54798603	KDNS: Cache HIT [httpbin.org -> 34.199.144.244]	
00000156	11.07181644	[KHTTP] GET /get (Host: httpbin.org:443, HTTPS: 1)	
00000157	11.07222271	[KHTTP] Receiving response (max 1048576 bytes)...	
00000158	11.27799511	[KHTTP] Received 225 bytes (total: 225)	
00000159	11.27800369	[KHTTP] Received 233 bytes (total: 458)	
00000160	11.27801037	[KHTTP] Connection closed, total received: 458 bytes	
00000161	11.27838516	[+] HTTPS GET - SUCCESS (Status: 200, Body: 233 bytes) 	
00000162	11.27838707	[Preview] {	
00000163	11.27838707	  "args": {}, 	
00000164	11.27838707	  "headers": {	
00000165	11.27838802	    "Accept": "application/json", 	
00000166	11.27838802	    "Host": "httpbin.org", 	
00000167	11.27838802	    "X-Amzn-Trace-Id": "Root=1-69aeada9-3cde3a3422ba579...	
00000168	11.27838993	 	
00000169	11.27838993	[HTTPS POST] httpbin.org/post	
00000170	11.27839184	[KHTTP] Connecting to httpbin.org:443 (HTTPS: 1)	
00000171	11.27839375	KDNS: Cache HIT [httpbin.org -> 34.199.144.244]	
00000172	11.80227375	[KHTTP] POST /post (Host: httpbin.org:443, HTTPS: 1)	
00000173	11.80260754	[KHTTP] Receiving response (max 1048576 bytes)...	
00000174	12.22244835	[KHTTP] Received 225 bytes (total: 225)	
00000175	12.22245884	[KHTTP] Received 447 bytes (total: 672)	
00000176	13.22389221	[KHTTP] Connection closed, total received: 672 bytes	
00000177	13.22590542	[+] HTTPS POST - SUCCESS (Status: 200) 	
00000178	13.22591209	 	
00000179	13.22591400	[HTTPS GET] jsonplaceholder.typicode.com/posts/1	
00000180	13.22592831	[KHTTP] Connecting to jsonplaceholder.typicode.com:443 (HTTPS: 1)	
00000181	13.22593689	KDNS: Cache HIT [jsonplaceholder.typicode.com -> 188.114.96.0]	
00000182	13.60732651	[KHTTP] GET /posts/1 (Host: jsonplaceholder.typicode.com:443, HTTPS: 1)	
00000183	13.60820007	[KHTTP] Receiving response (max 1048576 bytes)...	
00000184	13.67599487	[KHTTP] Received 1369 bytes (total: 1369)	
00000185	13.67601299	[KHTTP] Received 137 bytes (total: 1506)	
00000186	13.67602444	[KHTTP] Connection closed, total received: 1506 bytes	
00000187	13.67685890	[+] HTTPS REST API - SUCCESS (Status: 200) 	
00000188	13.67686272	[Preview] {	
00000189	13.67686272	  "userId": 1,	
00000190	13.67686272	  "id": 1,	
00000191	13.67686272	  "title": "sunt aut facere repellat provident occaecati excepturi optio...	
00000192	13.67686558	 	
00000193	13.67686749	[HTTPS HEAD] ya.ru	
00000194	13.67687035	[KHTTP] Connecting to ya.ru:443 (HTTPS: 1)	
00000195	13.67687321	KDNS: Cache HIT [ya.ru -> 5.255.255.242]	
00000196	34.70452499	[KHTTP] Connection failed: 0xC00000B5	
00000197	34.70455170	[-] HTTPS HEAD - FAILED (0xC00000B5) - Request failed 	
00000198	34.70455933	 	
00000199	34.70455933	[REST-HTTPS] GET /posts/1	
00000200	34.70457458	[KHTTP] Connecting to jsonplaceholder.typicode.com:443 (HTTPS: 1)	
00000201	34.70458603	KDNS: Cache HIT [jsonplaceholder.typicode.com -> 188.114.96.0]	
00000202	34.97116470	[KHTTP] GET /posts/1 (Host: jsonplaceholder.typicode.com:443, HTTPS: 1)	
00000203	34.97188568	[KHTTP] Receiving response (max 1048576 bytes)...	
00000204	35.04089355	[KHTTP] Received 1369 bytes (total: 1369)	
00000205	35.04091263	[KHTTP] Received 137 bytes (total: 1506)	
00000206	35.04092026	[KHTTP] Connection closed, total received: 1506 bytes	
00000207	35.04163361	[+] REST-HTTPS GET - SUCCESS (Status: 200) 	
00000208	35.04163742	 	
00000209	35.04163742	[REST-HTTPS] POST /posts	
00000210	35.04164505	[KHTTP] Connecting to jsonplaceholder.typicode.com:443 (HTTPS: 1)	
00000211	35.04164505	KDNS: Cache HIT [jsonplaceholder.typicode.com -> 188.114.96.0]	
00000212	35.30533981	[KHTTP] POST /posts (Host: jsonplaceholder.typicode.com:443, HTTPS: 1)	
00000213	35.30560684	[KHTTP] Receiving response (max 1048576 bytes)...	
00000214	35.46603012	[KHTTP] Received 1369 bytes (total: 1369)	
00000215	35.46605301	[KHTTP] Received 35 bytes (total: 1404)	
00000216	35.46606445	[KHTTP] Connection closed, total received: 1404 bytes	
00000217	35.46698380	[+] REST-HTTPS POST - SUCCESS (Status: 201) 	
00000218	35.46698761	 	
00000219	35.46698761	[REST-HTTPS] PUT /posts/1	
00000220	35.46699142	[KHTTP] Connecting to jsonplaceholder.typicode.com:443 (HTTPS: 1)	
00000221	35.46699524	KDNS: Cache HIT [jsonplaceholder.typicode.com -> 188.114.96.0]	
00000222	35.72887802	[KHTTP] PUT /posts/1 (Host: jsonplaceholder.typicode.com:443, HTTPS: 1)	
00000223	35.72914124	[KHTTP] Receiving response (max 1048576 bytes)...	
00000224	36.06338882	[KHTTP] Received 1278 bytes (total: 1278)	
00000225	36.06344604	[KHTTP] Connection closed, total received: 1278 bytes	
00000226	36.06591415	[+] REST-HTTPS PUT - SUCCESS (Status: 200) 	
00000227	36.06592178	 	
00000228	36.06592178	[REST-HTTPS] DELETE /posts/1	
00000229	36.06593704	[KHTTP] Connecting to jsonplaceholder.typicode.com:443 (HTTPS: 1)	
00000230	36.06594467	KDNS: Cache HIT [jsonplaceholder.typicode.com -> 188.114.96.0]	
00000231	36.33620071	[KHTTP] DELETE /posts/1 (Host: jsonplaceholder.typicode.com:443, HTTPS: 1)	
00000232	36.33667755	[KHTTP] Receiving response (max 1048576 bytes)...	
00000233	36.49121094	[KHTTP] Received 1198 bytes (total: 1198)	
00000234	36.49123383	[KHTTP] Connection closed, total received: 1198 bytes	
00000235	36.49208450	[+] REST-HTTPS DELETE - SUCCESS (Status: 200) 	
00000236	36.49208832	 	
00000237	36.49208832	========================================	
00000238	36.49209213	  FILE UPLOAD TESTS	
00000239	36.49209595	========================================	
00000240	36.49209595	 	
00000241	36.49209595	[UPLOAD] Single file test (1KB)	
00000242	36.49210739	[KHTTP] Starting multipart request to https://httpbin.org/post (chunked: 0, streaming: 0)	
00000243	36.49210739	[KHTTP] Generated boundary: ----0syMJCQzjHYOxPtER61ZEtSoXM9WrcrjpyHgcQT2	
00000244	36.49211502	[KHTTP] Connecting to httpbin.org:443 (HTTPS: 1)	
00000245	36.49211884	KDNS: Cache HIT [httpbin.org -> 34.199.144.244]	
00000246	37.01266098	[KHTTP] POST /post (Host: httpbin.org:443, HTTPS: 1)	
00000247	37.01267624	[KHTTP] Built multipart body: 1236 bytes	
00000248	37.01268005	[KHTTP] Built multipart body: 1236 bytes	
00000249	37.01317978	[KHTTP] Headers sent: 1441 bytes	
00000250	37.01384354	[KHTTP] Receiving response (max 1048576 bytes)...	
00000251	37.25688171	[KHTTP] Received 2086 bytes (total: 2086)	
00000252	38.25652313	[KHTTP] Connection closed, total received: 2086 bytes	
00000253	38.25678635	[KHTTP] Response received: status 200	
00000254	38.25740051	[+] Single File Upload - SUCCESS (Status: 200, Response: 1860 bytes) 	
00000255	40.26798630	 	
00000256	40.26798630	[UPLOAD] File with form fields (2KB)	
00000257	40.26803589	[KHTTP] Starting multipart request to https://example.com/upload (chunked: 0, streaming: 0)	
00000258	40.26804733	[KHTTP] Generated boundary: ----OFG1BbAnyJ0ZusE8aUjlLgEiD1NPRQG3gIYMz5uG	
00000259	40.26805115	[KHTTP] Connecting to example.com:443 (HTTPS: 1)	
00000260	40.26805496	KDNS: Cache miss, querying DNS	
00000261	40.26805496	KDNS: Resolving 'example.com' (depth=0, len=11)	
00000262	40.26805878	KDNS: Built query for 'example.com' (ID=0x8574, len=29)	
00000263	40.26815796	KDNS: TDI bound to port 50005	
00000264	40.26828766	KDNS: Sent 29 bytes	
00000265	40.33279419	KDNS: Received 83 bytes	
00000266	40.44374847	KDNS: Parsing 2 answer(s)	
00000267	40.44375229	KDNS: Found A record: 104.18.27.120	
00000268	40.44375610	KDNS: Resolution complete: example.com -> 104.18.27.120	
00000269	40.44375610	KDNS: Cached [example.com -> 104.18.27.120]	
00000270	40.73598099	[KHTTP] POST /upload (Host: example.com:443, HTTPS: 1)	
00000271	40.73598862	[KHTTP] Built multipart body: 2494 bytes	
00000272	40.73598862	[KHTTP] Built multipart body: 2494 bytes	
00000273	40.73622513	[KHTTP] Headers sent: 2669 bytes	
00000274	40.73649597	[KHTTP] Receiving response (max 1048576 bytes)...	
00000275	40.80975723	[KHTTP] Received 706 bytes (total: 706)	
00000276	40.80978012	[KHTTP] Received 5 bytes (total: 711)	
00000277	40.80979919	[KHTTP] Connection closed, total received: 711 bytes	
00000278	40.81010056	[KHTTP] Response received: status 405	
00000279	40.81079865	[+] File+Form Upload - SUCCESS (Status: 405) 	
00000280	42.82239532	 	
00000281	42.82239532	[UPLOAD] Multiple files with progress (512B + 1KB)	
00000282	42.82240677	[KHTTP] Starting multipart request to https://httpbin.org/post (chunked: 0, streaming: 0)	
00000283	42.82241821	[KHTTP] Generated boundary: ----VlVEkAsJtRcdrFLr25i6jn9h7Zcl1zZ0SiHbyCr2	
00000284	42.82242584	[KHTTP] Connecting to httpbin.org:443 (HTTPS: 1)	
00000285	42.82242584	KDNS: Cache HIT [httpbin.org -> 34.199.144.244]	
00000286	43.34867859	[KHTTP] POST /post (Host: httpbin.org:443, HTTPS: 1)	
00000287	43.34879684	[KHTTP] Built multipart body: 1900 bytes	
00000288	43.34880447	[KHTTP] Built multipart body: 1900 bytes	
00000289	43.35013962	[KHTTP] Headers sent: 2073 bytes	
00000290	43.35281754	[KHTTP] Receiving response (max 5242880 bytes)...	
00000291	43.51361847	[KHTTP] Received 226 bytes (total: 226)	
00000292	43.51379395	[KHTTP] Connection closed, total received: 226 bytes	
00000293	43.51496506	[KHTTP] Response received: status 200	
00000294	43.51578903	[+] Multiple Files Upload - SUCCESS (Status: 200) 	
00000295	45.52209473	 	
00000296	45.52209473	[UPLOAD] Large file chunked transfer (5MB)	
00000297	45.52636337	[KHTTP] Large body detected (5242880 bytes), enabling chunked transfer	
00000298	45.52636719	[KHTTP] Starting multipart request to http://192.168.56.1:8080/upload (chunked: 1, streaming: 0)	
00000299	45.52637863	[KHTTP] Generated boundary: ----UfxrXJqgO6z6MdCz7TTZlxnB99JhBkOkS8sHjLMj	
00000300	45.52638245	[KHTTP] Connecting to 192.168.56.1:8080 (HTTPS: 0)	
00000301	45.52638245	KDNS: Cache miss, querying DNS	
00000302	45.52638626	KDNS: Resolving '192.168.56.1' (depth=0, len=12)	
00000303	45.52638626	KDNS: Parsed IPv4: 192.168.56.1 -> 0x0138A8C0	
00000304	45.52639008	KDNS: Hostname is IP address, no DNS query needed	
00000305	45.52639008	KDNS: Cached [192.168.56.1 -> 192.168.56.1]	
00000306	45.52720642	[KHTTP] POST /upload (Host: 192.168.56.1:8080, HTTPS: 0)	
00000307	45.53143692	[KHTTP] Built multipart body: 5243097 bytes	
00000308	45.53144073	[KHTTP] Built multipart body: 5243097 bytes	
00000309	45.58374786	[KHTTP] Headers sent: 182 bytes	
00000310	54.50422287	[KHTTP] [STREAMING] Sending chunk terminator	
00000311	54.51097107	[KHTTP] Receiving response (max 5242880 bytes)...	
00000312	54.51101303	[KHTTP] Received 265 bytes (total: 265)	
00000313	54.51102066	[KHTTP] Connection closed, total received: 265 bytes	
00000314	54.51103210	[KHTTP] Response received: status 200	
00000315	54.51200104	[+] Large File Upload - SUCCESS (Status: 200, Size: 5242880 bytes) 	
00000316	56.52487564	 	
00000317	56.52487564	[UPLOAD] Streaming file from disk	
00000318	56.52489090	[KHTTP] Starting multipart request to https://192.168.56.1:8443/upload (chunked: 1, streaming: 1)	
00000319	56.52502441	[KHTTP] Generated boundary: ----udOpoK9uOinrpsYYhQYUXzlMRC5kq12xNzEvzWva	
00000320	56.52503586	[KHTTP] Connecting to 192.168.56.1:8443 (HTTPS: 1)	
00000321	56.52504349	KDNS: Cache HIT [192.168.56.1 -> 192.168.56.1]	
00000322	56.62911987	[KHTTP] POST /upload (Host: 192.168.56.1:8443, HTTPS: 1)	
00000323	56.62913132	[KHTTP] Using streaming mode	
00000324	56.67532730	[KHTTP] Headers sent: 182 bytes	
00000325	56.67534256	[KHTTP] Estimated multipart overhead: 221 bytes	
00000326	56.81479645	[PROGRESS] 72% (161/221 bytes)	
00000327	56.81492996	[KHTTP] [STREAMING] File size: 5193152 bytes	
00000328	56.81492996	[KHTTP] [STREAMING] Total size: 5193373 bytes (5193152 file + 221 overhead)	
00000329	56.92538071	[PROGRESS] 5% (262305/5193373 bytes)	
00000330	57.03308105	[PROGRESS] 10% (524449/5193373 bytes)	
00000331	57.13986588	[PROGRESS] 15% (786593/5193373 bytes)	
00000332	57.25171661	[PROGRESS] 20% (1048737/5193373 bytes)	
00000333	57.35998154	[PROGRESS] 25% (1310881/5193373 bytes)	
00000334	57.46833801	[PROGRESS] 30% (1573025/5193373 bytes)	
00000335	57.57740784	[PROGRESS] 35% (1835169/5193373 bytes)	
00000336	57.68887711	[PROGRESS] 40% (2097313/5193373 bytes)	
00000337	57.79752350	[PROGRESS] 45% (2359457/5193373 bytes)	
00000338	57.90647125	[PROGRESS] 50% (2621601/5193373 bytes)	
00000339	58.01845932	[PROGRESS] 55% (2883745/5193373 bytes)	
00000340	58.12860870	[PROGRESS] 60% (3145889/5193373 bytes)	
00000341	58.23598862	[PROGRESS] 65% (3408033/5193373 bytes)	
00000342	58.34412766	[PROGRESS] 70% (3670177/5193373 bytes)	
00000343	58.45264053	[PROGRESS] 75% (3932321/5193373 bytes)	
00000344	58.56338501	[PROGRESS] 80% (4194465/5193373 bytes)	
00000345	58.67054749	[PROGRESS] 85% (4456609/5193373 bytes)	
00000346	58.76401138	[PROGRESS] 90% (4718753/5193373 bytes)	
00000347	58.87379074	[PROGRESS] 95% (4980897/5193373 bytes)	
00000348	58.98035812	[PROGRESS] 99% (5193313/5193373 bytes)	
00000349	59.12259674	[PROGRESS] 99% (5193315/5193373 bytes)	
00000350	59.25932312	[PROGRESS] 99% (5193365/5193373 bytes)	
00000351	59.25933456	[KHTTP] [STREAMING] Sending chunk terminator	
00000352	59.26127243	[KHTTP] [DEBUG] No response buffer provided, skipping receive	
00000353	59.26257324	[+] Streaming Upload - SUCCESS (Upload failed or file not found) 	
00000354	59.26258087	 	
00000355	59.26258087	========================================	
00000356	59.26258087	  All Tests Completed	
00000357	59.26258469	========================================	
00000358	74.47496033	 	
00000359	74.47496033	========================================	
00000360	74.47496033	  Unloading Driver	
00000361	74.47496033	========================================	
00000362	74.47496033	KDNS: Cache cleanup (hits=16, misses=5, evictions=0)	
00000363	74.47496033	KDNS: Library cleanup complete	
00000364	74.47496033	[KHTTP] Cleaned up	
00000365	74.47496796	[+] Driver unloaded successfully	
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