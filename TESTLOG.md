```log
00000001	0.00000000	 	
00000002	0.00001050	[Driver] Windows Kernel HTTP Library	
00000003	0.00036530	KDNS: Cache initialized	
00000004	0.00039060	[KHTTP] Initialized	
00000005	0.00039920	 	
00000006	0.00040610	[DNS] Resolving ya.ru...	
00000007	0.00041590	KDNS: Resolving ya.ru using local port 50001 (depth: 0)	
00000008	0.00043440	KDNS: Binding to local port 50001	
00000009	0.00140850	KDNS: Sent 23 bytes from port 50001	
00000010	0.21352939	KDNS: Received 86 bytes on port 50001	
00000011	0.36767560	KDNS: Port 50001 released	
00000012	0.36769721	KDNS: Resolved ya.ru -> f2ffff05 (depth 0)	
00000013	0.58522379	KDNS: Cleanup completed for ya.ru (status: 0x00000000)	
00000014	0.58526742	[DNS] OK - IP: 05.ff.ff.f2	
00000015	0.58529031	 	
00000016	0.58530349	[TLS] Connecting to 1.1.1.1:4443...	
00000017	0.58550602	KTLS: SNI hostname set to: 1.1.1.1	
00000018	0.58629400	KTLS: Address opened successfully (Device: TCP)	
00000019	0.72943437	KTLS: Handshake successful	
00000020	0.72944951	[TLS] Connected	
00000021	0.73036402	[TLS] RX 71 bytes:	
00000022	0.73038220	[TLS-Server] Echo: GET / HTTP/1.1 	
00000023	0.73039252	Host: 1.1.1.1 	
00000024	0.73041201	Connection: close 	
00000025	0.73042279	 	
00000026	0.73043799	 	
00000027	0.73215681	 	
00000028	0.73217320	[DTLS] Connecting to 1.1.1.1:4443...	
00000029	0.73223412	KTLS: SNI hostname set to: 1.1.1.1	
00000030	0.73274088	KTLS: Address opened successfully (Device: UDP)	
00000031	0.85717851	KTLS: Handshake successful	
00000032	0.85719401	[DTLS] Connected	
00000033	1.05904543	[DTLS] RX 30 bytes:	
00000034	1.05906904	[DTLS-Server] Echo: Hello DTLS 	
00000035	1.05989158	 	
00000036	1.05990291	[HTTP] GET httpbin.org/get	
00000037	1.05992460	[KHTTP] GET /get (Host: httpbin.org:80, HTTPS: 0)	
00000038	1.05994046	KDNS: Cache miss for httpbin.org, performing DNS query	
00000039	1.05995595	KDNS: Resolving httpbin.org using local port 50002 (depth: 0)	
00000040	1.06042266	KDNS: Binding to local port 50002	
00000041	1.06149316	KDNS: Sent 29 bytes from port 50002	
00000042	2.06598163	KDNS: Received 191 bytes on port 50002	
00000043	2.22454405	KDNS: Port 50002 released	
00000044	2.22483730	KDNS: Resolved httpbin.org -> 3d5bc52c (depth 0)	
00000045	2.42582870	KDNS: Cleanup completed for httpbin.org (status: 0x00000000)	
00000046	2.42585230	KDNS: Cached httpbin.org -> 3D5BC52C	
00000047	2.42619729	KTLS: Address opened successfully (Device: TCP)	
00000048	5.92464256	[HTTP] Status 200, Size 197	
00000049	5.92467499	 	
00000050	5.92468262	[HTTP] POST httpbin.org/post	
00000051	5.92469501	[KHTTP] POST /post (Host: httpbin.org:80, HTTPS: 0)	
00000052	5.92470646	KDNS: Cache hit for httpbin.org -> 3D5BC52C	
00000053	5.92488527	KTLS: Address opened successfully (Device: TCP)	
00000054	9.20240402	[HTTP] Status 200	
00000055	9.20244026	 	
00000056	9.20244694	[HTTP] HEAD ya.ru	
00000057	9.20245934	[KHTTP] HEAD / (Host: ya.ru:80, HTTPS: 0)	
00000058	9.20247078	KDNS: Cache miss for ya.ru, performing DNS query	
00000059	9.20248032	KDNS: Resolving ya.ru using local port 50003 (depth: 0)	
00000060	9.20249271	KDNS: Binding to local port 50003	
00000061	9.20326042	KDNS: Sent 23 bytes from port 50003	
00000062	9.20525169	KDNS: Received 86 bytes on port 50003	
00000063	9.36057377	KDNS: Port 50003 released	
00000064	9.36058998	KDNS: Resolved ya.ru -> f2ffff05 (depth 0)	
00000065	9.56247807	KDNS: Cleanup completed for ya.ru (status: 0x00000000)	
00000066	9.56250191	KDNS: Cached ya.ru -> F2FFFF05	
00000067	9.56284809	KTLS: Address opened successfully (Device: TCP)	
00000068	13.09317398	[HTTP] Status 301, Body 0 bytes	
00000069	13.09320831	 	
00000070	13.09321594	[REST] GET /posts/1	
00000071	13.09323597	[KHTTP] GET /posts/1 (Host: jsonplaceholder.typicode.com:80, HTTPS: 0)	
00000072	13.09324741	KDNS: Cache miss for jsonplaceholder.typicode.com, performing DNS query	
00000073	13.09325790	KDNS: Resolving jsonplaceholder.typicode.com using local port 50004 (depth: 0)	
00000074	13.09327030	KDNS: Binding to local port 50004	
00000075	13.09398746	KDNS: Sent 46 bytes from port 50004	
00000076	13.72995663	KDNS: Received 134 bytes on port 50004	
00000077	13.89119053	KDNS: Port 50004 released	
00000078	13.89121628	KDNS: Resolved jsonplaceholder.typicode.com -> 006172bc (depth 0)	
00000079	14.10659981	KDNS: Cleanup completed for jsonplaceholder.typicode.com (status: 0x00000000)	
00000080	14.10662746	KDNS: Cached jsonplaceholder.typicode.com -> 006172BC	
00000081	14.10716438	KTLS: Address opened successfully (Device: TCP)	
00000082	16.88203812	[REST] Status 200	
00000083	16.88207054	 	
00000084	16.88207626	[REST] POST /posts	
00000085	16.88208961	[KHTTP] POST /posts (Host: jsonplaceholder.typicode.com:80, HTTPS: 0)	
00000086	16.88210106	KDNS: Cache hit for jsonplaceholder.typicode.com -> 006172BC	
00000087	16.88230324	KTLS: Address opened successfully (Device: TCP)	
00000088	19.64722824	[REST] Status 201	
00000089	19.64726067	 	
00000090	19.64726639	[REST] PUT /posts/1	
00000091	19.64728165	[KHTTP] PUT /posts/1 (Host: jsonplaceholder.typicode.com:80, HTTPS: 0)	
00000092	19.64729309	KDNS: Cache hit for jsonplaceholder.typicode.com -> 006172BC	
00000093	19.64748573	KTLS: Address opened successfully (Device: TCP)	
00000094	22.41193008	[REST] Status 200	
00000095	22.41197014	 	
00000096	22.41198158	[REST] PATCH /posts/1	
00000097	22.41200256	[KHTTP] PATCH /posts/1 (Host: jsonplaceholder.typicode.com:80, HTTPS: 0)	
00000098	22.41201973	KDNS: Cache hit for jsonplaceholder.typicode.com -> 006172BC	
00000099	22.41222000	KTLS: Address opened successfully (Device: TCP)	
00000100	24.97251701	[REST] Status 200	
00000101	24.97256088	 	
00000102	24.97257233	[REST] DELETE /posts/1	
00000103	24.97259331	[KHTTP] DELETE /posts/1 (Host: jsonplaceholder.typicode.com:80, HTTPS: 0)	
00000104	24.97261047	KDNS: Cache hit for jsonplaceholder.typicode.com -> 006172BC	
00000105	24.97307587	KTLS: Address opened successfully (Device: TCP)	
00000106	29.98935318	[REST] Status 200	
00000107	29.98945618	 	
00000108	29.98946571	[HTTPS] GET httpbin.org/get	
00000109	29.98948479	[KHTTP] GET /get (Host: httpbin.org:443, HTTPS: 1)	
00000110	29.98950005	KDNS: Cache hit for httpbin.org -> 3D5BC52C	
00000111	29.98969841	KTLS: SNI hostname set to: httpbin.org	
00000112	29.98997688	KTLS: Address opened successfully (Device: TCP)	
00000113	31.75381851	KTLS: Handshake successful	
00000114	31.75383759	KTLS: ALPN protocol: http/1.1	
00000115	31.95903397	[HTTPS] Status 200, Size 233	
00000116	31.95904922	[HTTPS] Body: {	
00000117	31.95905685	  "args": {}, 	
00000118	31.95906639	  "headers": {	
00000119	31.95907211	    "Accept": "application/json", 	
00000120	31.95907784	    "Host": "httpbin.org", 	
00000121	31.95908546	    "X-Amzn-Trace-Id": "Root=1-6985e9b6-31b2de0549fc0e6...	
00000122	31.95911026	 	
00000123	31.95911980	[HTTPS] POST httpbin.org/post	
00000124	31.95913315	[KHTTP] POST /post (Host: httpbin.org:443, HTTPS: 1)	
00000125	31.95914268	KDNS: Cache hit for httpbin.org -> 3D5BC52C	
00000126	31.95918465	KTLS: SNI hostname set to: httpbin.org	
00000127	31.95936394	KTLS: Address opened successfully (Device: TCP)	
00000128	34.87332535	KTLS: Handshake successful	
00000129	34.87334061	KTLS: ALPN protocol: http/1.1	
00000130	38.79706955	[HTTPS] Status 200	
00000131	38.79710388	 	
00000132	38.79711151	[HTTPS] GET jsonplaceholder.typicode.com/posts/1	
00000133	38.79712296	[KHTTP] GET /posts/1 (Host: jsonplaceholder.typicode.com:443, HTTPS: 1)	
00000134	38.79713440	KDNS: Cache hit for jsonplaceholder.typicode.com -> 006172BC	
00000135	38.79718018	KTLS: SNI hostname set to: jsonplaceholder.typicode.com	
00000136	38.79735184	KTLS: Address opened successfully (Device: TCP)	
00000137	40.24283981	KTLS: Handshake successful	
00000138	40.24286652	KTLS: ALPN protocol: http/1.1	
00000139	42.30204773	[HTTPS] Status 200	
00000140	42.30207443	[HTTPS] Body: {	
00000141	42.30208206	  "userId": 1,	
00000142	42.30209732	  "id": 1,	
00000143	42.30211258	  "title": "sunt aut facere repellat provident occaecati excepturi optio...	
00000144	42.30213928	 	
00000145	42.30214691	[HTTPS] HEAD ya.ru	
00000146	42.30215836	[KHTTP] HEAD / (Host: ya.ru:443, HTTPS: 1)	
00000147	42.30217361	KDNS: Cache hit for ya.ru -> F2FFFF05	
00000148	42.30227661	KTLS: SNI hostname set to: ya.ru	
00000149	42.30247116	KTLS: Address opened successfully (Device: TCP)	
00000150	43.01646805	KTLS: Handshake successful	
00000151	43.01648331	KTLS: ALPN protocol: http/1.1	
00000152	43.22935104	[HTTPS] Status 200, Body 0 bytes	
00000153	43.22939301	 	
00000154	43.22940063	[REST-HTTPS] GET /posts/1	
00000155	43.22941589	[KHTTP] GET /posts/1 (Host: jsonplaceholder.typicode.com:443, HTTPS: 1)	
00000156	43.22943497	KDNS: Cache hit for jsonplaceholder.typicode.com -> 006172BC	
00000157	43.22949600	KTLS: SNI hostname set to: jsonplaceholder.typicode.com	
00000158	43.23007202	KTLS: Address opened successfully (Device: TCP)	
00000159	46.39604950	KTLS: Handshake successful	
00000160	46.39606857	KTLS: ALPN protocol: http/1.1	
00000161	46.50033951	[REST-HTTPS] Status 200	
00000162	46.50037384	 	
00000163	46.50038147	[REST-HTTPS] POST /posts	
00000164	46.50039291	[KHTTP] POST /posts (Host: jsonplaceholder.typicode.com:443, HTTPS: 1)	
00000165	46.50040817	KDNS: Cache hit for jsonplaceholder.typicode.com -> 006172BC	
00000166	46.50063324	KTLS: SNI hostname set to: jsonplaceholder.typicode.com	
00000167	46.50082397	KTLS: Address opened successfully (Device: TCP)	
00000168	48.44401550	KTLS: Handshake successful	
00000169	48.44403076	KTLS: ALPN protocol: http/1.1	
00000170	48.65046310	[REST-HTTPS] Status 201	
00000171	48.65049744	 	
00000172	48.65050125	[REST-HTTPS] PUT /posts/1	
00000173	48.65051651	[KHTTP] PUT /posts/1 (Host: jsonplaceholder.typicode.com:443, HTTPS: 1)	
00000174	48.65052414	KDNS: Cache hit for jsonplaceholder.typicode.com -> 006172BC	
00000175	48.65056992	KTLS: SNI hostname set to: jsonplaceholder.typicode.com	
00000176	48.65076828	KTLS: Address opened successfully (Device: TCP)	
00000177	50.49266815	KTLS: Handshake successful	
00000178	50.49268341	KTLS: ALPN protocol: http/1.1	
00000179	51.62029266	[REST-HTTPS] Status 200	
00000180	51.62034988	 	
00000181	51.62035751	[REST-HTTPS] DELETE /posts/1	
00000182	51.62037277	[KHTTP] DELETE /posts/1 (Host: jsonplaceholder.typicode.com:443, HTTPS: 1)	
00000183	51.62038422	KDNS: Cache hit for jsonplaceholder.typicode.com -> 006172BC	
00000184	51.62047195	KTLS: SNI hostname set to: jsonplaceholder.typicode.com	
00000185	51.62065506	KTLS: Address opened successfully (Device: TCP)	
00000186	52.33544159	KTLS: Handshake successful	
00000187	52.33546066	KTLS: ALPN protocol: http/1.1	
00000188	52.55338669	[REST-HTTPS] Status 200	
00000189	52.55342484	[KHTTP] Starting multipart request to https://httpbin.org/post	
00000190	52.55344391	[KHTTP] Generated boundary: ----24OiS3SDga5YQ0ZyJ8VxQWWe7N8kXZuWVN0pF4K1	
00000191	52.55345535	[KHTTP] Built multipart body: 1236 bytes	
00000192	52.55346680	[KHTTP] Built multipart body: 1236 bytes	
00000193	52.55347824	[KHTTP] Making HTTP request	
00000194	52.55348969	[KHTTP] POST /post (Host: httpbin.org:443, HTTPS: 1)	
00000195	52.55349731	KDNS: Cache hit for httpbin.org -> 3D5BC52C	
00000196	52.55353546	KTLS: SNI hostname set to: httpbin.org	
00000197	52.55373764	KTLS: Address opened successfully (Device: TCP)	
00000198	53.57344818	KTLS: Handshake successful	
00000199	53.57346725	KTLS: ALPN protocol: http/1.1	
00000200	55.79491806	[KHTTP] Request completed: 0x00000000	
00000201	55.79497147	[KHTTP] Upload status: 200	
00000202	55.79498291	[KHTTP] Response body length: 1860	
00000203	57.80470276	[KHTTP] Starting multipart request to https://example.com/upload	
00000204	57.80475998	[KHTTP] Generated boundary: ----h9jZEjGbQe0Z9eNblNDWwjotltQvMfdZ8cYXnf2c	
00000205	57.80478668	[KHTTP] Built multipart body: 2477 bytes	
00000206	57.80479813	[KHTTP] Built multipart body: 2477 bytes	
00000207	57.80482101	[KHTTP] Making HTTP request	
00000208	57.80484009	[KHTTP] POST /upload (Host: example.com:443, HTTPS: 1)	
00000209	57.80485916	KDNS: Cache miss for example.com, performing DNS query	
00000210	57.80487061	KDNS: Resolving example.com using local port 50005 (depth: 0)	
00000211	57.80491638	KDNS: Binding to local port 50005	
00000212	57.80579376	KDNS: Sent 29 bytes from port 50005	
00000213	57.96977234	KDNS: Received 83 bytes on port 50005	
00000214	58.12197876	KDNS: Port 50005 released	
00000215	58.12200165	KDNS: Resolved example.com -> 781a1268 (depth 0)	
00000216	58.32305908	KDNS: Cleanup completed for example.com (status: 0x00000000)	
00000217	58.32308960	KDNS: Cached example.com -> 781A1268	
00000218	58.32323837	KTLS: SNI hostname set to: example.com	
00000219	58.32348251	KTLS: Address opened successfully (Device: TCP)	
00000220	59.09523010	KTLS: Handshake successful	
00000221	59.09524536	KTLS: ALPN protocol: http/1.1	
00000222	59.30157471	[KHTTP] Request completed: 0x00000000	
00000223	59.30162430	[KHTTP] Upload completed: 405	
00000224	61.30821609	[KHTTP] Starting multipart request to https://httpbin.org/post	
00000225	61.30826187	[KHTTP] Generated boundary: ----slGLDn9TF7rQnplAV96GUrm7OoNFd0zZX3ZHsgQP	
00000226	61.30827332	[KHTTP] Built multipart body: 1900 bytes	
00000227	61.30828857	[KHTTP] Built multipart body: 1900 bytes	
00000228	61.30830002	[KHTTP] Making HTTP request	
00000229	61.30831528	[KHTTP] POST /post (Host: httpbin.org:443, HTTPS: 1)	
00000230	61.30832672	KDNS: Cache hit for httpbin.org -> 3D5BC52C	
00000231	61.30841064	KTLS: SNI hostname set to: httpbin.org	
00000232	61.30866623	KTLS: Address opened successfully (Device: TCP)	
00000233	62.47319794	KTLS: Handshake successful	
00000234	62.47321701	KTLS: ALPN protocol: http/1.1	
00000235	64.01581573	[KHTTP] Request completed: 0x00000000	
00000236	64.01586914	[KHTTP] Multiple files uploaded: 200	
00000237	66.02862549	[KHTTP] Large body detected (5242880 bytes), enabling chunked transfer	
00000238	66.02864075	[KHTTP] Starting multipart request to https://httpbin.org/post (chunked: 1)	
00000239	66.04899597	[KHTTP] Built multipart body: 5243097 bytes	
00000240	66.04901886	[KHTTP] Built multipart body: 5243097 bytes	
00000241	66.04904938	KDNS: Cache hit for httpbin.org -> 3D5BC52C	
00000242	66.04914093	KTLS: SNI hostname set to: httpbin.org	
00000243	66.04940033	KTLS: Address opened successfully (Device: TCP)	
00000244	67.08484650	KTLS: Handshake successful	
00000245	67.08486176	KTLS: ALPN protocol: http/1.1	
00000246	67.08556366	[KHTTP] Starting chunked transfer: 5243097 bytes (chunk: 65536)	
00000247	67.10507202	[KHTTP] Sent: 655360/5243097 bytes (12%)	
00000248	67.12341309	[KHTTP] Sent: 1310720/5243097 bytes (24%)	
00000249	67.14465332	[KHTTP] Sent: 1966080/5243097 bytes (37%)	
00000250	67.16476440	[KHTTP] Sent: 2621440/5243097 bytes (49%)	
00000251	67.18486023	[KHTTP] Sent: 3276800/5243097 bytes (62%)	
00000252	67.20494843	[KHTTP] Sent: 3932160/5243097 bytes (74%)	
00000253	67.22424316	[KHTTP] Sent: 4587520/5243097 bytes (87%)	
00000254	67.24534607	[KHTTP] Sent: 5242880/5243097 bytes (99%)	
00000255	67.24678040	[KHTTP] Sent: 5243097/5243097 bytes (100%)	
00000256	67.24747467	[KHTTP] Chunked transfer complete: 5243097 bytes	
00000257	69.03249359	[KHTTP] Large file uploaded: 200 (size: 5242880 bytes)	
00000258	69.03405762	 	
00000259	69.03406525	[Driver] Tests complete	
00000260	92.58624268	KDNS: Cache cleaned up	
00000261	92.58626556	[KHTTP] Cleaned up	
00000262	92.58627319	 	
00000263	92.58628845	[Driver] Unloaded	
```