import os
import sys
from phases.phase2_symbex import generate_and_run_harness

#juliet test : CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_01_bad
# metadata = {
#     'function_name': 'CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_01_bad',
#     'cwe_id': 'CWE-122: Heap-based Buffer Overflow',
#     'file_path': '/home/cks/Project/SE-LLM-project/juliet-test-suite-c/testcases/CWE122_Heap_Based_Buffer_Overflow/s01/CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_01.c',
#     'slice': """void CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_01_bad()
# {
#     {
#         charVoid * structCharVoid = (charVoid *)malloc(sizeof(charVoid));
#         if (structCharVoid == NULL) {exit(-1);}
#         structCharVoid->voidSecond = (void *)SRC_STR;
#         /* Print the initial block pointed to by structCharVoid->voidSecond */
#         printLine((char *)structCharVoid->voidSecond);
#         /* FLAW: Use the sizeof(*structCharVoid) which will overwrite the pointer y */
#         memcpy(structCharVoid->charFirst, SRC_STR, sizeof(*structCharVoid));
#         structCharVoid->charFirst[(sizeof(structCharVoid->charFirst)/sizeof(char))-1] = '\\0'; /* null terminate the string */
#         printLine((char *)structCharVoid->charFirst);
#         printLine((char *)structCharVoid->voidSecond);
#         free(structCharVoid);
#     }
# }"""
# }

#juliet test : CWE-122: Heap-based Buffer Overflow (CWE-129: Improper Validation of Array Index)
# metadata = {
#     'function_name': 'bad',
#     'cwe_id': 'CWE-122: Heap-based Buffer Overflow (CWE-129: Improper Validation of Array Index)',
#     'file_path': '/home/cks/Project/SE-LLM-project/juliet-test-suite-c/testcases/CWE122_Heap_Based_Buffer_Overflow/s01/CWE122_Heap_Based_Buffer_Overflow__cpp_CWE129_fscanf_02.cpp',
#     'slice': """void bad()
# {
#     int data;
#     /* Initialize data */
#     data = -1;
#     if(1)
#     {
#         /* POTENTIAL FLAW: Read data from the console using fscanf() */
#         fscanf(stdin, "%d", &data);
#     }
#     if(1)
#     {
#         {
#             int i;
#             int * buffer = new int[10];
#             /* initialize buffer */
#             for (i = 0; i < 10; i++)
#             {
#                 buffer[i] = 0;
#             }
#             /* POTENTIAL FLAW: Attempt to write to an index of the array that is above the upper bound
#              * This code does check to see if the array index is negative */
#             if (data >= 0)
#             {
#                 buffer[data] = 1;
#                 /* Print the array values */
#                 for(i = 0; i < 10; i++)
#                 {
#                     printIntLine(buffer[i]);
#                 }
#             }
#             else
#             {
#                 printLine("ERROR: Array index is negative.");
#             }
#             delete[] buffer;
#         }
#     }
# }"""
# }

# tcpdump
metadata = {
    'function_name': 'bootp_print',
    'cwe_id': 'CWE-125: Out-of-bounds Read',
    'file_path': '/home/cks/Project/SE-LLM-project/tcpdump-4.9.1/print-bootp.c',
    'slice': """void
bootp_print(netdissect_options *ndo,
	    register const u_char *cp, u_int length)
{
	register const struct bootp *bp;
	static const u_char vm_cmu[4] = VM_CMU;
	static const u_char vm_rfc1048[4] = VM_RFC1048;

	bp = (const struct bootp *)cp;
	ND_TCHECK(bp->bp_op);

	ND_PRINT((ndo, "BOOTP/DHCP, %s",
		  tok2str(bootp_op_values, "unknown (0x%02x)", bp->bp_op)));

	ND_TCHECK(bp->bp_hlen);
	if (bp->bp_htype == 1 && bp->bp_hlen == 6 && bp->bp_op == BOOTPREQUEST) {
		ND_TCHECK2(bp->bp_chaddr[0], 6);
		ND_PRINT((ndo, " from %s", etheraddr_string(ndo, bp->bp_chaddr)));
	}

	ND_PRINT((ndo, ", length %u", length));

	if (!ndo->ndo_vflag)
		return;

	ND_TCHECK(bp->bp_secs);

	/* The usual hardware address type is 1 (10Mb Ethernet) */
	if (bp->bp_htype != 1)
		ND_PRINT((ndo, ", htype %d", bp->bp_htype));

	/* The usual length for 10Mb Ethernet address is 6 bytes */
	if (bp->bp_htype != 1 || bp->bp_hlen != 6)
		ND_PRINT((ndo, ", hlen %d", bp->bp_hlen));

	/* Only print interesting fields */
	if (bp->bp_hops)
		ND_PRINT((ndo, ", hops %d", bp->bp_hops));
	if (EXTRACT_32BITS(&bp->bp_xid))
		ND_PRINT((ndo, ", xid 0x%x", EXTRACT_32BITS(&bp->bp_xid)));
	if (EXTRACT_16BITS(&bp->bp_secs))
		ND_PRINT((ndo, ", secs %d", EXTRACT_16BITS(&bp->bp_secs)));

	ND_PRINT((ndo, ", Flags [%s]",
		  bittok2str(bootp_flag_values, "none", EXTRACT_16BITS(&bp->bp_flags))));
	if (ndo->ndo_vflag > 1)
		ND_PRINT((ndo, " (0x%04x)", EXTRACT_16BITS(&bp->bp_flags)));

	/* Client's ip address */
	ND_TCHECK(bp->bp_ciaddr);
	if (EXTRACT_32BITS(&bp->bp_ciaddr.s_addr))
		ND_PRINT((ndo, "\n\t  Client-IP %s", ipaddr_string(ndo, &bp->bp_ciaddr)));

	/* 'your' ip address (bootp client) */
	ND_TCHECK(bp->bp_yiaddr);
	if (EXTRACT_32BITS(&bp->bp_yiaddr.s_addr))
		ND_PRINT((ndo, "\n\t  Your-IP %s", ipaddr_string(ndo, &bp->bp_yiaddr)));

	/* Server's ip address */
	ND_TCHECK(bp->bp_siaddr);
	if (EXTRACT_32BITS(&bp->bp_siaddr.s_addr))
		ND_PRINT((ndo, "\n\t  Server-IP %s", ipaddr_string(ndo, &bp->bp_siaddr)));

	/* Gateway's ip address */
	ND_TCHECK(bp->bp_giaddr);
	if (EXTRACT_32BITS(&bp->bp_giaddr.s_addr))
		ND_PRINT((ndo, "\n\t  Gateway-IP %s", ipaddr_string(ndo, &bp->bp_giaddr)));

	/* Client's Ethernet address */
	if (bp->bp_htype == 1 && bp->bp_hlen == 6) {
		ND_TCHECK2(bp->bp_chaddr[0], 6);
		ND_PRINT((ndo, "\n\t  Client-Ethernet-Address %s", etheraddr_string(ndo, bp->bp_chaddr)));
	}

	ND_TCHECK2(bp->bp_sname[0], 1);		/* check first char only */
	if (*bp->bp_sname) {
		ND_PRINT((ndo, "\n\t  sname \""));
		if (fn_printztn(ndo, bp->bp_sname, (u_int)sizeof bp->bp_sname,
		    ndo->ndo_snapend)) {
			ND_PRINT((ndo, "\""));
			ND_PRINT((ndo, "%s", tstr + 1));
			return;
		}
		ND_PRINT((ndo, "\""));
	}
	ND_TCHECK2(bp->bp_file[0], 1);		/* check first char only */
	if (*bp->bp_file) {
		ND_PRINT((ndo, "\n\t  file \""));
		if (fn_printztn(ndo, bp->bp_file, (u_int)sizeof bp->bp_file,
		    ndo->ndo_snapend)) {
			ND_PRINT((ndo, "\""));
			ND_PRINT((ndo, "%s", tstr + 1));
			return;
		}
		ND_PRINT((ndo, "\""));
	}

	/* Decode the vendor buffer */
	ND_TCHECK(bp->bp_vend[0]);
	if (memcmp((const char *)bp->bp_vend, vm_rfc1048,
		    sizeof(uint32_t)) == 0)
		rfc1048_print(ndo, bp->bp_vend);
	else if (memcmp((const char *)bp->bp_vend, vm_cmu,
			sizeof(uint32_t)) == 0)
		cmu_print(ndo, bp->bp_vend);
	else {
		uint32_t ul;

		ul = EXTRACT_32BITS(&bp->bp_vend);
		if (ul != 0)
			ND_PRINT((ndo, "\n\t  Vendor-#0x%x", ul));
	}

	return;
trunc:
	ND_PRINT((ndo, "%s", tstr));
}"""
}

target_binary = '/home/cks/Project/SE-LLM-project/target_bin'

try:
    poc_path = generate_and_run_harness(metadata, target_binary)
    print("PHASE2 SUCCESS!")
    print("PoC Path:", poc_path)
    
    if os.path.exists('angr_harness.py'):
        with open('angr_harness.py', 'r') as f:
            print("\\n--- generated angr_harness.py ---")
            print(f.read())
            print("---------------------------------")
except Exception as e:
    print("PHASE2 ERROR:", str(e))
