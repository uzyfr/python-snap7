#!/usr/bin/env python

__author__ = "Aleksandr Timorin"
__copyright__ = "Copyright 2013, Positive Technologies"
__license__ = "GNU GPL v3"
__version__ = "1.7"
__maintainer__ = "Aleksandr Timorin"
__email__ = "atimorin@gmail.com"
__status__ = "Development"


# 2do:
# - show packets with required value in required place

import sys
import dpkt
from struct import unpack as unp
from copy import deepcopy
# ----------------------------------------



# Returnvalues of an item response
s7comm_item_return_valuenames = {
  0x00 : ( 'S7COMM_ITEM_RETVAL_RESERVED', "Reserved" ),
  0x01 : ( 'S7COMM_ITEM_RETVAL_DATA_HW_FAULT', "Hardware error" ),
  0x03 : ( 'S7COMM_ITEM_RETVAL_DATA_ACCESS_FAULT', "Accessing the object not allowed" ),
  0x05 : ( 'S7COMM_ITEM_RETVAL_DATA_OUTOFRANGE', "Invalid address: the desired address is beyond limit for this PLC" ),
  0x06 : ( 'S7COMM_ITEM_RETVAL_DATA_NOT_SUP', "Data type not supported" ),
  0x07 : ( 'S7COMM_ITEM_RETVAL_DATA_SIZEMISMATCH', "Data type inconsistent" ),
  0x0a : ( 'S7COMM_ITEM_RETVAL_DATA_ERR', "Object does not exist: the desired item is not available in the PLC, e.g. when trying to read a non existing DB" ),
  0xff : ( 'S7COMM_ITEM_RETVAL_DATA_OK', "Success" ),
}

# PDU types
rosctr_names = {
  0x01: ( 'S7COMM_ROSCTR_JOB', "Job: Request: job with acknowledgement" ),
  0x02: ( 'S7COMM_ROSCTR_ACK', "Ack: acknowledgement without additional field" ),
  0x03: ( 'S7COMM_ROSCTR_ACK_DATA', "Ack_Data: Response: acknowledgement with additional field" ),
  0x07: ( 'S7COMM_ROSCTR_USERDATA', "Userdata" ),
}

# Names of userdata subfunctions in group 4 (CPU functions)
userdata_cpu_subfunc_names = {
  0x01 : ( 'S7COMM_UD_SUBF_CPU_READSZL', "Read SZL" ),
  0x02 : ( 'S7COMM_UD_SUBF_CPU_MSGS', "Message service" ),
  0x03 : ( 'S7COMM_UD_SUBF_CPU_DIAGMSG', "Diagnostic message from PLC" ),
  0x05 : ( 'S7COMM_UD_SUBF_CPU_ALARM8_IND', "ALARM_8 indication: PLC is indicating an ALARM message, using ALARM_8 SFBs" ),
  0x06 : ( 'S7COMM_UD_SUBF_CPU_NOTIFY_IND', "NOTIFY indication: PLC is indicating a NOTIFY message, using NOTIFY SFBs" ),
  0x07 : ( 'S7COMM_UD_SUBF_CPU_ALARM8LOCK', "ALARM_8 lock: Lock an ALARM message from HMI/SCADA" ),
  0x08 : ( 'S7COMM_UD_SUBF_CPU_ALARM8UNLOCK', "ALARM_8 unlock: Unlock an ALARM message from HMI/SCADA" ),
  0x0b : ( 'S7COMM_UD_SUBF_CPU_ALARMACK', "Alarm was acknowledged in HMI/SCADA" ),
  0x0c : ( 'S7COMM_UD_SUBF_CPU_ALARMACK_IND', "Alarm acknowledge indication from CPU to HMI" ),
  0x0d : ( 'S7COMM_UD_SUBF_CPU_ALARM8LOCK_IND', "Alarm lock indication from CPU to HMI" ),
  0x0e : ( 'S7COMM_UD_SUBF_CPU_ALARM8UNLOCK_IND', "Alarm unlock indication from CPU to HMI" ),
  0x11 : ( 'S7COMM_UD_SUBF_CPU_ALARMSQ_IND', "ALARM_SQ indication: PLC is indicating an ALARM message, using ALARM_SQ/ALARM_DQ SFCs" ),
  0x12 : ( 'S7COMM_UD_SUBF_CPU_ALARMS_IND', "ALARM_S indication: PLC is indicating an ALARM message, using ALARM_S/ALARM_D SFCs" ),
  0x13 : ( 'S7COMM_UD_SUBF_CPU_ALARMQUERY', "ALARM query: HMI/SCADA query of ALARMs" ),
  0x16 : ( 'S7COMM_UD_SUBF_CPU_NOTIFY8_IND', "NOTIFY_8 indication" ),
}

# Names of userdata subfunctions in group 5 (Security?)
userdata_sec_subfunc_names = {
  0x01 : ( 'S7COMM_UD_SUBF_SEC_PASSWD', "PLC password" ),
}

# Names of userdata subfunctions in group 7 (Time functions)
userdata_time_subfunc_names = {
  0x01 : ( 'S7COMM_UD_SUBF_TIME_READ', "Read clock" ),
  0x02 : ( 'S7COMM_UD_SUBF_TIME_SET', "Set clock" ),
  0x03 : ( 'S7COMM_UD_SUBF_TIME_READF', "Read clock (following)" ),
  0x04 : ( 'S7COMM_UD_SUBF_TIME_SET2', "Set clock" ),
}

# Weekday names in DATE_AND_TIME
weekdaynames = {
  0 : "Undefined",
  1 : "Sunday",
  2 : "Monday",
  3 : "Tuesday",
  4 : "Wednesday",
  5 : "Thursday",
  6 : "Friday",
  7 : "Saturday",
}

# Flags for LID access
tia1200_var_lid_flag_names = {
  0x2 : ( 'S7COMM_TIA1200_VAR_ENCAPS_LID', "Encapsulated LID" ),
  0x3 : ( 'S7COMM_TIA1200_VAR_ENCAPS_IDX', "Encapsulated Index" ),
  0x4 : ( 'S7COMM_TIA1200_VAR_OBTAIN_LID', "Obtain by LID" ),
  0x5 : ( 'S7COMM_TIA1200_VAR_OBTAIN_IDX', "Obtain by Index" ),
  0x6 : ( 'S7COMM_TIA1200_VAR_PART_START', "Part Start Address" ),
  0x7 : ( 'S7COMM_TIA1200_VAR_PART_LEN', "Part Length" ),
}

# TIA 1200 Area Names for variable access
tia1200_var_item_area1_names = {
  0x8a0e : ( 'S7COMM_TIA1200_VAR_ITEM_AREA1_DB', "DB: Reading DB, 2 byte DB-Number following" ),
  0x0000 : ( 'S7COMM_TIA1200_VAR_ITEM_AREA1_IQMCT', "IQMCT: Reading I/Q/M/C/T, 2 Byte detail area following" ),
}

tia1200_var_item_area2_names = {
  0x50 : ( 'S7COMM_TIA1200_VAR_ITEM_AREA2_I', "Inputs (I)" ),
  0x51 : ( 'S7COMM_TIA1200_VAR_ITEM_AREA2_Q', "Outputs (Q)" ),
  0x52 : ( 'S7COMM_TIA1200_VAR_ITEM_AREA2_M', "Flags (M)" ),
  0x53 : ( 'S7COMM_TIA1200_VAR_ITEM_AREA2_C', "Counter (C)" ),
  0x54 : ( 'S7COMM_TIA1200_VAR_ITEM_AREA2_T', "Timer (T)" ),
}

# NCK areas
nck_area_names = {
  0: ( 'S7COMM_NCK_AREA_N_NCK',                "N - NCK" ),
  1: ( 'S7COMM_NCK_AREA_B_MODEGROUP',          "B - Mode group" ),
  2: ( 'S7COMM_NCK_AREA_C_CHANNEL',            "C - Channel" ),
  3: ( 'S7COMM_NCK_AREA_A_AXIS',               "A - Axis" ),
  4: ( 'S7COMM_NCK_AREA_T_TOOL',               "T - Tool" ),
  5: ( 'S7COMM_NCK_AREA_V_FEEDDRIVE',          "V - Feed drive" ),
  6: ( 'S7COMM_NCK_AREA_H_MAINDRIVE',          "M - Main drive" ),
  7: ( 'S7COMM_NCK_AREA_M_MMC',                "M - MMC" ),
}

nck_module_names = {
  0x10: "Y - Global system data",
  0x11: "YNCFL - NCK instruction groups",
  0x12: "FU - NCU global settable frames",
  0x13: "FA - Active NCU global frames",
  0x14: "TO - Tool data",
  0x15: "RP - Arithmetic parameters",
  0x16: "SE - Setting data",
  0x17: "SGUD - SGUD-Block",
  0x18: "LUD - Local userdata",
  0x19: "TC - Toolholder parameters",
  0x1a: "M - Machine data",
  0x1c: "WAL - Working area limitation",
  0x1e: "DIAG - Internal diagnostic data",
  0x1f: "CC - Unknown",
  0x20: "FE - Channel-specific external frame",
  0x21: "TD - Tool data: General data",
  0x22: "TS - Tool edge data: Monitoring data",
  0x23: "TG - Tool data: Grinding-specific data",
  0x24: "TU - Tool data",
  0x25: "TUE - Tool edge data, userdefined data",
  0x26: "TV - Tool data, directory",
  0x27: "TM - Magazine data: General data",
  0x28: "TP - Magazine data: Location data",
  0x29: "TPM - Magazine data: Multiple assignment of location data",
  0x2a: "TT - Magazine data: Location typ",
  0x2b: "TMV - Magazine data: Directory",
  0x2c: "TMC - Magazine data: Configuration data",
  0x2d: "MGUD - MGUD-Block",
  0x2e: "UGUD - UGUD-Block",
  0x2f: "GUD4 - GUD4-Block",
  0x30: "GUD5 - GUD5-Block",
  0x31: "GUD6 - GUD6-Block",
  0x32: "GUD7 - GUD7-Block",
  0x33: "GUD8 - GUD8-Block",
  0x34: "GUD9 - GUD9-Block",
  0x35: "PA - Channel-specific protection zones",
  0x36: "GD1 - SGUD-Block GD1",
  0x37: "NIB - State data: Nibbling",
  0x38: "ETP - Types of events",
  0x39: "ETPD - Data lists for protocolling",
  0x3a: "SYNACT - Channel-specific synchronous actions",
  0x3b: "DIAGN - Diagnostic data",
  0x3c: "VSYN - Channel-specific user variables for synchronous actions",
  0x3d: "TUS - Tool data: user monitoring data",
  0x3e: "TUM - Tool data: user magazine data",
  0x3f: "TUP - Tool data: user magatine place data",
  0x40: "TF - Parametrizing, return parameters of _N_TMGETT, _N_TSEARC",
  0x41: "FB - Channel-specific base frames",
  0x42: "SSP2 - State data: Spindle",
  0x43: "PUD - programmglobale Benutzerdaten",
  0x44: "TOS - Edge-related location-dependent fine total offsets",
  0x45: "TOST - Edge-related location-dependent fine total offsets, transformed",
  0x46: "TOE - Edge-related coarse total offsets, setup offsets",
  0x47: "TOET - Edge-related coarse total offsets, transformed setup offsets",
  0x48: "AD - Adapter data",
  0x49: "TOT - Edge data: Transformed offset data",
  0x4a: "AEV - Working offsets: Directory",
  0x4b: "YFAFL - NCK instruction groups (Fanuc)",
  0x4c: "FS - System-Frame",
  0x4d: "SD - Servo data",
  0x4e: "TAD - Application-specific data",
  0x4f: "TAO - Aplication-specific cutting edge data",
  0x50: "TAS - Application-specific monitoring data",
  0x51: "TAM - Application-specific magazine data",
  0x52: "TAP - Application-specific magazine location data",
  0x53: "MEM - Unknown",
  0x54: "SALUC - Alarm actions: List in reverse chronological order",
  0x55: "AUXFU - Auxiliary functions",
  0x56: "TDC - Tool/Tools",
  0x57: "CP - Generic coupling",
  0x6e: "SDME - Unknown",
  0x6f: "SPARPI - Program pointer on interruption",
  0x70: "SEGA - State data: Geometry axes in tool offset memory (extended)",
  0x71: "SEMA - State data: Machine axes (extended)",
  0x72: "SSP - State data: Spindle",
  0x73: "SGA - State data: Geometry axes in tool offset memory",
  0x74: "SMA - State data: Machine axes",
  0x75: "SALAL - Alarms: List organized according to time",
  0x76: "SALAP - Alarms: List organized according to priority",
  0x77: "SALA - Alarms: List organized according to time",
  0x78: "SSYNAC - Synchronous actions",
  0x79: "SPARPF - Program pointers for block search and stop run",
  0x7a: "SPARPP - Program pointer in automatic operation",
  0x7b: "SNCF - Active G functions",
  0x7d: "SPARP - Part program information",
  0x7e: "SINF - Part-program-specific status data",
  0x7f: "S - State data",
  0x80: "0x80 - Unknown",
  0x81: "0x81 - Unknown",
  0x82: "0x82 - Unknown",
  0x83: "0x83 - Unknown",
  0x84: "0x84 - Unknown",
  0x85: "0x85 - Unknown",
  0xfd: "0 - Internal",
}

hf_s7comm_tia1200_item_reserved1 = -1    # 1 Byte Reserved (always 0xff?)
hf_s7comm_tia1200_item_area1 = -1        # 2 Byte2 Root area (DB or IQMCT)
hf_s7comm_tia1200_item_area2 = -1        # 2 Bytes detail area (I/Q/M/C/T)
hf_s7comm_tia1200_item_area2unknown = -1 # 2 Bytes detail area for possible unknown or not seen areas
hf_s7comm_tia1200_item_dbnumber = -1     # 2 Bytes DB number
hf_s7comm_tia1200_item_crc = -1          # 4 Bytes CRC

hf_s7comm_tia1200_substructure_item = -1 # Substructure
hf_s7comm_tia1200_var_lid_flags = -1     # LID Flags
hf_s7comm_tia1200_item_value = -1


# Description for PI service names
pi_service_names = {
  0: ( "UNKNOWN", "PI-Service is currently unknown" ),
  1: ( "_INSE",  "PI-Service _INSE (Activates a PLC module)" ),
  1: ( "_DELE",  "PI-Service _DELE (Removes module from the PLC's passive file system)" ),
  1: ( "P_PROGRAM",  "PI-Service P_PROGRAM (PLC Start / Stop)" ),
  1: ( "_MODU",  "PI-Service _MODU (PLC Copy Ram to Rom)" ),
  1: ( "_GARB",  "PI-Service _GARB (Compress PLC memory)" ),
  1: ( "_N_LOGIN_",  "PI-Service _N_LOGIN_ (Login)" ),
  1: ( "_N_LOGOUT",  "PI-Service _N_LOGOUT (Logout)" ),
  1: ( "_N_CANCEL",  "PI-Service _N_CANCEL (Cancels NC alarm)" ),
  1: ( "_N_DASAVE",  "PI-Service _N_DASAVE (PI-Service for copying data from SRAM to FLASH)" ),
  1: ( "_N_DIGIOF",  "PI-Service _N_DIGIOF (Turns off digitizing)" ),
  1: ( "_N_DIGION",  "PI-Service _N_DIGION (Turns on digitizing)" ),
  1: ( "_N_DZERO_",  "PI-Service _N_DZERO_ (Set all D nos. invalid for function \"unique D no.\")" ),
  1: ( "_N_ENDEXT",  "PI-Service _N_ENDEXT ()" ),
  1: ( "_N_F_OPER",  "PI-Service _N_F_OPER (Opens a file read-only)" ),
  1: ( "_N_OST_OF",  "PI-Service _N_OST_OF (Overstore OFF)" ),
  1: ( "_N_OST_ON",  "PI-Service _N_OST_ON (Overstore ON)" ),
  1: ( "_N_SCALE_",  "PI-Service _N_SCALE_ (Unit of measurement setting (metric<->INCH))" ),
  1: ( "_N_SETUFR",  "PI-Service _N_SETUFR (Activates user frame)" ),
  1: ( "_N_STRTLK",  "PI-Service _N_STRTLK (The global start disable is set)" ),
  1: ( "_N_STRTUL",  "PI-Service _N_STRTUL (The global start disable is reset)" ),
  1: ( "_N_TMRASS",  "PI-Service _N_TMRASS (Resets the Active status)" ),
  1: ( "_N_F_DELE",  "PI-Service _N_F_DELE (Deletes file)" ),
  1: ( "_N_EXTERN",  "PI-Service _N_EXTERN (Selects external program for execution)" ),
  1: ( "_N_EXTMOD",  "PI-Service _N_EXTMOD (Selects external program for execution)" ),
  1: ( "_N_F_DELR",  "PI-Service _N_F_DELR (Delete file even without access rights)" ),
  1: ( "_N_F_XFER",  "PI-Service _N_F_XFER (Selects file for uploading)" ),
  1: ( "_N_LOCKE_",  "PI-Service _N_LOCKE_ (Locks the active file for editing)" ),
  1: ( "_N_SELECT",  "PI-Service _N_SELECT (Selects program for execution)" ),
  1: ( "_N_SRTEXT",  "PI-Service _N_SRTEXT (A file is being marked in /_N_EXT_DIR)" ),
  1: ( "_N_F_CLOS",  "PI-Service _N_F_CLOS (Closes file)" ),
  1: ( "_N_F_OPEN",  "PI-Service _N_F_OPEN (Opens file)" ),
  1: ( "_N_F_SEEK",  "PI-Service _N_F_SEEK (Position the file search pointer)" ),
  1: ( "_N_ASUP__",  "PI-Service _N_ASUP__ (Assigns interrupt)" ),
  1: ( "_N_CHEKDM",  "PI-Service _N_CHEKDM (Start uniqueness check on D numbers)" ),
  1: ( "_N_CHKDNO",  "PI-Service _N_CHKDNO (Check whether the tools have unique D numbers)" ),
  1: ( "_N_CONFIG",  "PI-Service _N_CONFIG (Reconfigures machine data)" ),
  1: ( "_N_CRCEDN",  "PI-Service _N_CRCEDN (Creates a cutting edge by specifying an edge no.)" ),
  1: ( "_N_DELECE",  "PI-Service _N_DELECE (Deletes a cutting egde)" ),
  1: ( "_N_CREACE",  "PI-Service _N_CREACE (Creates a cutting edge)" ),
  1: ( "_N_CREATO",  "PI-Service _N_CREATO (Creates a tool)" ),
  1: ( "_N_DELETO",  "PI-Service _N_DELETO (Deletes tool)" ),
  1: ( "_N_CRTOCE",  "PI-Service _N_CRTOCE (Generate tool with specified edge number)" ),
  1: ( "_N_DELVAR",  "PI-Service _N_DELVAR (Delete data block)" ),
  1: ( "_N_F_COPY",  "PI-Service _N_F_COPY (Copies file within the NCK)" ),
  1: ( "_N_F_DMDA",  "PI-Service _N_F_DMDA (Deletes MDA memory)" ),
  1: ( "_N_F_PROT",  "PI-Service _N_F_PROT (Assigns a protection level to a file)" ),
  1: ( "_N_F_RENA",  "PI-Service _N_F_RENA (Renames file)" ),
  1: ( "_N_FINDBL",  "PI-Service _N_FINDBL (Activates search)" ),
  1: ( "_N_IBN_SS",  "PI-Service _N_IBN_SS (Sets the set-up switch)" ),
  1: ( "_N_MMCSEM",  "PI-Service _N_MMCSEM (MMC-Semaphore)" ),
  1: ( "_N_NCKMOD",  "PI-Service _N_NCKMOD (The mode in which the NCK will work is being set)" ),
  1: ( "_N_NEWPWD",  "PI-Service _N_NEWPWD (New password)" ),
  1: ( "_N_SEL_BL",  "PI-Service _N_SEL_BL (Selects a new block)" ),
  1: ( "_N_SETTST",  "PI-Service _N_SETTST (Activate tools for replacement tool group)" ),
  1: ( "_N_TMAWCO",  "PI-Service _N_TMAWCO (Set the active wear group in one magazine)" ),
  1: ( "_N_TMCRTC",  "PI-Service _N_TMCRTC (Create tool with specified edge number)" ),
  1: ( "_N_TMCRTO",  "PI-Service _N_TMCRTO (Creates tool in the tool management)" ),
  1: ( "_N_TMFDPL",  "PI-Service _N_TMFDPL (Searches an empty place for loading)" ),
  1: ( "_N_TMFPBP",  "PI-Service _N_TMFPBP (Searches for empty location)" ),
  1: ( "_N_TMGETT",  "PI-Service _N_TMGETT (Determines T-number for specific toolID with Duplono)" ),
  1: ( "_N_TMMVTL",  "PI-Service _N_TMMVTL (Loads or unloads a tool)" ),
  1: ( "_N_TMPCIT",  "PI-Service _N_TMPCIT (Sets increment value of the piece counter)" ),
  1: ( "_N_TMPOSM",  "PI-Service _N_TMPOSM (Positions a magazine or tool)" ),
  1: ( "_N_TRESMO",  "PI-Service _N_TRESMO (Reset monitoring values)" ),
  1: ( "_N_TSEARC",  "PI-Service _N_TSEARC (Complex search via search screenforms)" ),
}

'''
# Function 0x28 (PI Start)
static gint hf_s7comm_piservice_unknown1 = -1;   /* Unknown bytes
static gint hf_s7comm_piservice_parameterblock = -1;
static gint hf_s7comm_piservice_parameterblock_len = -1;
static gint hf_s7comm_piservice_servicename = -1;

static gint ett_s7comm_piservice_parameterblock = -1;

static gint hf_s7comm_piservice_string_len = -1;
static gint hf_s7comm_pi_n_x_addressident = -1;
static gint hf_s7comm_pi_n_x_password = -1;
static gint hf_s7comm_pi_n_x_filename = -1;
static gint hf_s7comm_pi_n_x_editwindowname = -1;
static gint hf_s7comm_pi_n_x_seekpointer = -1;
static gint hf_s7comm_pi_n_x_windowsize = -1;
static gint hf_s7comm_pi_n_x_comparestring = -1;
static gint hf_s7comm_pi_n_x_skipcount = -1;
static gint hf_s7comm_pi_n_x_interruptnr = -1;
static gint hf_s7comm_pi_n_x_priority = -1;
static gint hf_s7comm_pi_n_x_liftfast = -1;
static gint hf_s7comm_pi_n_x_blsync = -1;
static gint hf_s7comm_pi_n_x_magnr = -1;
static gint hf_s7comm_pi_n_x_dnr = -1;
static gint hf_s7comm_pi_n_x_spindlenumber = -1;
static gint hf_s7comm_pi_n_x_wznr = -1;
static gint hf_s7comm_pi_n_x_class = -1;
static gint hf_s7comm_pi_n_x_tnr = -1;
static gint hf_s7comm_pi_n_x_toolnumber = -1;
static gint hf_s7comm_pi_n_x_cenumber = -1;
static gint hf_s7comm_pi_n_x_datablocknumber = -1;
static gint hf_s7comm_pi_n_x_firstcolumnnumber = -1;
static gint hf_s7comm_pi_n_x_lastcolumnnumber = -1;
static gint hf_s7comm_pi_n_x_firstrownumber = -1;
static gint hf_s7comm_pi_n_x_lastrownumber = -1;
static gint hf_s7comm_pi_n_x_direction = -1;
static gint hf_s7comm_pi_n_x_sourcefilename = -1;
static gint hf_s7comm_pi_n_x_destinationfilename = -1;
static gint hf_s7comm_pi_n_x_channelnumber = -1;
static gint hf_s7comm_pi_n_x_protection = -1;
static gint hf_s7comm_pi_n_x_oldfilename = -1;
static gint hf_s7comm_pi_n_x_newfilename = -1;
static gint hf_s7comm_pi_n_x_findmode = -1;
static gint hf_s7comm_pi_n_x_switch = -1;
static gint hf_s7comm_pi_n_x_functionnumber = -1;
static gint hf_s7comm_pi_n_x_semaphorvalue = -1;
static gint hf_s7comm_pi_n_x_onoff = -1;
static gint hf_s7comm_pi_n_x_mode = -1;
static gint hf_s7comm_pi_n_x_factor = -1;
static gint hf_s7comm_pi_n_x_passwordlevel = -1;
static gint hf_s7comm_pi_n_x_linenumber = -1;
static gint hf_s7comm_pi_n_x_weargroup = -1;
static gint hf_s7comm_pi_n_x_toolstatus = -1;
static gint hf_s7comm_pi_n_x_wearsearchstrat = -1;
static gint hf_s7comm_pi_n_x_toolid = -1;
static gint hf_s7comm_pi_n_x_duplonumber = -1;
static gint hf_s7comm_pi_n_x_edgenumber = -1;
static gint hf_s7comm_pi_n_x_placenr = -1;
static gint hf_s7comm_pi_n_x_placerefnr = -1;
static gint hf_s7comm_pi_n_x_magrefnr = -1;
static gint hf_s7comm_pi_n_x_magnrfrom = -1;
static gint hf_s7comm_pi_n_x_placenrfrom = -1;
static gint hf_s7comm_pi_n_x_magnrto = -1;
static gint hf_s7comm_pi_n_x_placenrto = -1;
static gint hf_s7comm_pi_n_x_halfplacesleft = -1;
static gint hf_s7comm_pi_n_x_halfplacesright = -1;
static gint hf_s7comm_pi_n_x_halfplacesup = -1;
static gint hf_s7comm_pi_n_x_halfplacesdown = -1;
static gint hf_s7comm_pi_n_x_placetype = -1;
static gint hf_s7comm_pi_n_x_searchdirection = -1;
static gint hf_s7comm_pi_n_x_toolname = -1;
static gint hf_s7comm_pi_n_x_placenrsource = -1;
static gint hf_s7comm_pi_n_x_magnrsource = -1;
static gint hf_s7comm_pi_n_x_placenrdestination = -1;
static gint hf_s7comm_pi_n_x_magnrdestination = -1;
static gint hf_s7comm_pi_n_x_incrementnumber = -1;
static gint hf_s7comm_pi_n_x_monitoringmode = -1;
static gint hf_s7comm_pi_n_x_kindofsearch = -1;

static gint hf_s7comm_data_plccontrol_argument = -1;        /* Argument, 2 Bytes as char
static gint hf_s7comm_data_plccontrol_block_cnt = -1;       /* Number of blocks, 1 Byte as int
static gint hf_s7comm_data_pi_inse_unknown = -1;
static gint hf_s7comm_data_plccontrol_part2_len = -1;       /* Length part 2 in bytes, 1 Byte as Int */

/* block control functions */
static gint hf_s7comm_data_blockcontrol_unknown1 = -1;      /* for all unknown bytes in blockcontrol */
static gint hf_s7comm_data_blockcontrol_errorcode = -1;     /* Error code 2 bytes as int, 0 is no error */
static gint hf_s7comm_data_blockcontrol_uploadid = -1;
static gint hf_s7comm_data_blockcontrol_file_ident = -1;    /* File identifier, as ASCII */
static gint hf_s7comm_data_blockcontrol_block_type = -1;    /* Block type, 2 Byte */
static gint hf_s7comm_data_blockcontrol_block_num = -1;     /* Block number, 5 Bytes, ASCII */
static gint hf_s7comm_data_blockcontrol_dest_filesys = -1;  /* Destination filesystem, 1 Byte, ASCII */
static gint hf_s7comm_data_blockcontrol_part2_len = -1;     /* Length part 2 in bytes, 1 Byte Int */
static gint hf_s7comm_data_blockcontrol_part2_unknown = -1; /* Unknown char, ASCII */
static gint hf_s7comm_data_blockcontrol_loadmem_len = -1;   /* Length load memory in bytes, ASCII */
static gint hf_s7comm_data_blockcontrol_mc7code_len = -1;   /* Length of MC7 code in bytes, ASCII */
static gint hf_s7comm_data_blockcontrol_filename_len = -1;
static gint hf_s7comm_data_blockcontrol_filename = -1;
static gint hf_s7comm_data_blockcontrol_upl_lenstring_len = -1;
static gint hf_s7comm_data_blockcontrol_upl_lenstring = -1;

static gint hf_s7comm_data_blockcontrol_functionstatus = -1;
static gint hf_s7comm_data_blockcontrol_functionstatus_more = -1;
static gint hf_s7comm_data_blockcontrol_functionstatus_error = -1;
static gint ett_s7comm_data_blockcontrol_status = -1;
static const int *s7comm_data_blockcontrol_status_fields[] = {
    &hf_s7comm_data_blockcontrol_functionstatus_more,
    &hf_s7comm_data_blockcontrol_functionstatus_error,
    NULL
};

static gint ett_s7comm_plcfilename = -1;
static gint hf_s7comm_data_ncprg_unackcount = -1;

/* Variable table */
static gint hf_s7comm_vartab_data_type = -1;                /* Type of data, 1 byte, stringlist userdata_prog_vartab_type_names */
static gint hf_s7comm_vartab_byte_count = -1;               /* Byte count, 2 bytes, int */
static gint hf_s7comm_vartab_unknown = -1;                  /* Unknown byte(s), hex */
static gint hf_s7comm_vartab_item_count = -1;               /* Item count, 2 bytes, int */
static gint hf_s7comm_vartab_req_memory_area = -1;          /* Memory area, 1 byte, stringlist userdata_prog_vartab_area_names  */
static gint hf_s7comm_vartab_req_repetition_factor = -1;    /* Repetition factor, 1 byte as int */
static gint hf_s7comm_vartab_req_db_number = -1;            /* DB number, 2 bytes as int */
static gint hf_s7comm_vartab_req_startaddress = -1;         /* Startaddress, 2 bytes as int */

/* cyclic data */
static gint hf_s7comm_cycl_interval_timebase = -1;          /* Interval timebase, 1 byte, int */
static gint hf_s7comm_cycl_interval_time = -1;              /* Interval time, 1 byte, int */

/* PBC, Programmable Block Functions */
static gint hf_s7comm_pbc_unknown = -1;                     /* unknown, 1 byte */
static gint hf_s7comm_pbc_r_id = -1;                        /* Request ID R_ID, 4 bytes as hex */

/* Alarm messages */
static gint hf_s7comm_cpu_alarm_message_item = -1;
static gint hf_s7comm_cpu_alarm_message_obj_item = -1;
static gint hf_s7comm_cpu_alarm_message_function = -1;
static gint hf_s7comm_cpu_alarm_message_nr_objects = -1;
static gint hf_s7comm_cpu_alarm_message_nr_add_values = -1;
static gint hf_s7comm_cpu_alarm_message_eventid = -1;
static gint hf_s7comm_cpu_alarm_message_timestamp_coming = -1;
static gint hf_s7comm_cpu_alarm_message_timestamp_going = -1;
static gint hf_s7comm_cpu_alarm_message_associated_value = -1;
static gint hf_s7comm_cpu_alarm_message_eventstate = -1;
static gint hf_s7comm_cpu_alarm_message_state = -1;
static gint hf_s7comm_cpu_alarm_message_ackstate_coming = -1;
static gint hf_s7comm_cpu_alarm_message_ackstate_going = -1;
static gint hf_s7comm_cpu_alarm_message_event_coming = -1;
static gint hf_s7comm_cpu_alarm_message_event_going = -1;
static gint hf_s7comm_cpu_alarm_message_event_lastchanged = -1;
static gint hf_s7comm_cpu_alarm_message_event_reserved = -1;

static gint hf_s7comm_cpu_alarm_message_signal_sig1 = -1;
static gint hf_s7comm_cpu_alarm_message_signal_sig2 = -1;
static gint hf_s7comm_cpu_alarm_message_signal_sig3 = -1;
static gint hf_s7comm_cpu_alarm_message_signal_sig4 = -1;
static gint hf_s7comm_cpu_alarm_message_signal_sig5 = -1;
static gint hf_s7comm_cpu_alarm_message_signal_sig6 = -1;
static gint hf_s7comm_cpu_alarm_message_signal_sig7 = -1;
static gint hf_s7comm_cpu_alarm_message_signal_sig8 = -1;
static gint ett_s7comm_cpu_alarm_message_signal = -1;
static const int *s7comm_cpu_alarm_message_signal_fields[] = {
    &hf_s7comm_cpu_alarm_message_signal_sig1,
    &hf_s7comm_cpu_alarm_message_signal_sig2,
    &hf_s7comm_cpu_alarm_message_signal_sig3,
    &hf_s7comm_cpu_alarm_message_signal_sig4,
    &hf_s7comm_cpu_alarm_message_signal_sig5,
    &hf_s7comm_cpu_alarm_message_signal_sig6,
    &hf_s7comm_cpu_alarm_message_signal_sig7,
    &hf_s7comm_cpu_alarm_message_signal_sig8,
    NULL
};

static gint hf_s7comm_cpu_alarm_query_unknown1 = -1;
static gint hf_s7comm_cpu_alarm_query_querytype = -1;
static gint hf_s7comm_cpu_alarm_query_unknown2 = -1;
static gint hf_s7comm_cpu_alarm_query_alarmtype = -1;
static gint hf_s7comm_cpu_alarm_query_completelen = -1;
static gint hf_s7comm_cpu_alarm_query_datasetlen = -1;
static gint hf_s7comm_cpu_alarm_query_resunknown1 = -1;

/* CPU diagnostic messages */
static gint hf_s7comm_cpu_diag_msg_item = -1;
static gint hf_s7comm_cpu_diag_msg_eventid = -1;
static gint hf_s7comm_cpu_diag_msg_eventid_class = -1;
static gint hf_s7comm_cpu_diag_msg_eventid_ident_entleave = -1;
static gint hf_s7comm_cpu_diag_msg_eventid_ident_diagbuf = -1;
static gint hf_s7comm_cpu_diag_msg_eventid_ident_interr = -1;
static gint hf_s7comm_cpu_diag_msg_eventid_ident_exterr = -1;
static gint hf_s7comm_cpu_diag_msg_eventid_nr = -1;
static gint hf_s7comm_cpu_diag_msg_prioclass = -1;
static gint hf_s7comm_cpu_diag_msg_obnumber = -1;
static gint hf_s7comm_cpu_diag_msg_datid = -1;
static gint hf_s7comm_cpu_diag_msg_info1 = -1;
static gint hf_s7comm_cpu_diag_msg_info2 = -1;

static gint ett_s7comm_cpu_diag_msg_eventid = -1;
static const int *s7comm_cpu_diag_msg_eventid_fields[] = {
    &hf_s7comm_cpu_diag_msg_eventid_class,
    &hf_s7comm_cpu_diag_msg_eventid_ident_entleave,
    &hf_s7comm_cpu_diag_msg_eventid_ident_diagbuf,
    &hf_s7comm_cpu_diag_msg_eventid_ident_interr,
    &hf_s7comm_cpu_diag_msg_eventid_ident_exterr,
    &hf_s7comm_cpu_diag_msg_eventid_nr,
    NULL
};

'''
tfs_s7comm_cpu_diag_msg_eventid_ident_entleave = ( "Event entering", "Event leaving" )

cpu_diag_msg_eventid_class_names = {
  0x01: "Standard OB events",
  0x02: "Synchronous errors",
  0x03: "Asynchronous errors",
  0x04: "Mode transitions",
  0x05: "Run-time events",
  0x06: "Communication events",
  0x07: "Events for fail-safe and fault-tolerant systems",
  0x08: "Standardized diagnostic data on modules",
  0x09: "Predefined user events",
  0x0a: "Freely definable events",
  0x0b: "Freely definable events",
  0x0c: "Reserved",
  0x0d: "Reserved",
  0x0e: "Reserved",
  0x0f: "Events for modules other than CPUs",
}

cpu_diag_eventid_fix_names = {
  0x113A: "Start request for cyclic interrupt OB with special handling (S7-300 only)",
  0x1155: "Status alarm for PROFIBUS DP",
  0x1156: "Update interrupt for PROFIBUS DP",
  0x1157: "Manufacturer interrupt for PROFIBUS DP",
  0x1158: "Status interrupt for PROFINET IO",
  0x1159: "Update interrupt for PROFINET IO",
  0x115A: "Manufacturer interrupt for PROFINET IO",
  0x115B: "IO: Profile-specific interrupt",
  0x116A: "Technology synchronization interrupt",
  0x1381: "Request for manual warm restart",
  0x1382: "Request for automatic warm restart",
  0x1383: "Request for manual hot restart",
  0x1384: "Request for automatic hot restart",
  0x1385: "Request for manual cold restart",
  0x1386: "Request for automatic cold restart",
  0x1387: "Master CPU: request for manual cold restart",
  0x1388: "Master CPU: request for automatic cold restart",
  0x138A: "Master CPU: request for manual warm restart",
  0x138B: "Master CPU: request for automatic warm restart",
  0x138C: "Standby CPU: request for manual hot restart",
  0x138D: "Standby CPU: request for automatic hot restart",
  0x2521: "BCD conversion error",
  0x2522: "Area length error when reading",
  0x2523: "Area length error when writing",
  0x2524: "Area error when reading",
  0x2525: "Area error when writing",
  0x2526: "Timer number error",
  0x2527: "Counter number error",
  0x2528: "Alignment error when reading",
  0x2529: "Alignment error when writing",
  0x2530: "Write error when accessing the DB",
  0x2531: "Write error when accessing the DI",
  0x2532: "Block number error when opening a DB",
  0x2533: "Block number error when opening a DI",
  0x2534: "Block number error when calling an FC",
  0x2535: "Block number error when calling an FB",
  0x253A: "DB not loaded",
  0x253C: "FC not loaded",
  0x253D: "SFC not loaded",
  0x253E: "FB not loaded",
  0x253F: "SFB not loaded",
  0x2942: "I/O access error, reading",
  0x2943: "I/O access error, writing",
  0x3267: "End of module reconfiguration",
  0x3367: "Start of module reconfiguration",
  0x34A4: "PROFInet Interface DB can be addressed again",
  0x3501: "Cycle time exceeded",
  0x3502: "User interface (OB or FRB) request error",
  0x3503: "Delay too long processing a priority class",
  0x3505: "Time-of-day interrupt(s) skipped due to new clock setting",
  0x3506: "Time-of-day interrupt(s) skipped when changing to RUN after HOLD",
  0x3507: "Multiple OB request errors caused internal buffer overflow",
  0x3508: "Synchronous cycle interrupt-timing error",
  0x3509: "Interrupt loss due to excess interrupt load",
  0x350A: "Resume RUN mode after CiR",
  0x350B: "Technology synchronization interrupt - timing error",
  0x3571: "Nesting depth too high in nesting levels",
  0x3572: "Nesting depth for Master Control Relays too high",
  0x3573: "Nesting depth too high after synchronous errors",
  0x3574: "Nesting depth for block calls (U stack) too high",
  0x3575: "Nesting depth for block calls (B stack) too high",
  0x3576: "Local data allocation error",
  0x3578: "Unknown instruction",
  0x357A: "Jump instruction to target outside of the block",
  0x3582: "Memory error detected and corrected by operating system",
  0x3583: "Accumulation of detected and corrected memo errors",
  0x3585: "Error in the PC operating system (only for LC RTX)",
  0x3587: "Multi-bit memory error detected and corrected",
  0x35A1: "User interface (OB or FRB) not found",
  0x35A2: "OB not loaded (started by SFC or operating system due to configuration)",
  0x35A3: "Error when operating system accesses a block",
  0x35A4: "PROFInet Interface DB cannot be addressed",
  0x35D2: "Diagnostic entries cannot be sent at present",
  0x35D3: "Synchronization frames cannot be sent",
  0x35D4: "Illegal time jump resulting from synchronization",
  0x35D5: "Error adopting the synchronization time",
  0x35E1: "Incorrect frame ID in GD",
  0x35E2: "GD packet status cannot be entered in DB",
  0x35E3: "Frame length error in GD",
  0x35E4: "Illegal GD packet number received",
  0x35E5: "Error accessing DB in communication SFBs for configured S7 connections",
  0x35E6: "GD total status cannot be entered in DB",
  0x3821: "BATTF: failure on at least one backup battery of the central rack, problem eliminated",
  0x3822: "BAF: failure of backup voltage on central rack, problem eliminated",
  0x3823: "24 volt supply failure on central rack, problem eliminated",
  0x3825: "BATTF: failure on at least one backup battery of the redundant central rack, problem eliminated",
  0x3826: "BAF: failure of backup voltage on redundant central rack, problem eliminated",
  0x3827: "24 volt supply failure on redundant central rack, problem eliminated",
  0x3831: "BATTF: failure of at least one backup battery of the expansion rack, problem eliminated",
  0x3832: "BAF: failure of backup voltage on expansion rack, problem eliminated",
  0x3833: "24 volt supply failure on at least one expansion rack, problem eliminated",
  0x3842: "Module OK",
  0x3854: "PROFINET IO interface submodule/submodule and matches the configured interface submodule/submodule",
  0x3855: "PROFINET IO interface submodule/submodule inserted, but does not match the configured interface submodule/submodule",
  0x3856: "PROFINET IO interface submodule/submodule inserted, but error in module parameter assignment",
  0x3858: "PROFINET IO interface submodule access error corrected",
  0x3861: "Module/interface module inserted, module type OK",
  0x3863: "Module/interface module plugged in, but wrong module type",
  0x3864: "Module/interface module plugged in, but causing problem (type ID unreadable)",
  0x3865: "Module plugged in, but error in module parameter assignment",
  0x3866: "Module can be addressed again, load voltage error removed",
  0x3881: "Interface error leaving state",
  0x3884: "Interface module plugged in",
  0x38B3: "I/O access error when updating the process image input table",
  0x38B4: "I/O access error when transferring the process image to the output modules",
  0x38C1: "Expansion rack operational again (1 to 21), leaving state",
  0x38C2: "Expansion rack operational again but mismatch between setpoint and actual configuration",
  0x38C4: "Distributed I/Os: station failure, leaving state",
  0x38C5: "Distributed I/Os: station fault, leaving state",
  0x38C6: "Expansion rack operational again, but error(s) in module parameter assignment",
  0x38C7: "DP: station operational again, but error(s) in module parameter assignment",
  0x38C8: "DP: station operational again, but mismatch between setpoint and actual configuration",
  0x38CB: "PROFINET IO station operational again",
  0x38CC: "PROFINET IO station error corrected",
  0x3921: "BATTF: failure on at least one backup battery of the central rack",
  0x3922: "BAF: failure of backup voltage on central rack",
  0x3923: "24 volt supply failure on central rack",
  0x3925: "BATTF: failure on at least one backup battery of the redundant central rack",
  0x3926: "BAF: failure of backup voltage on redundant central rack",
  0x3927: "24 volt supply failure on redundant central rack",
  0x3931: "BATTF: failure of at least one backup battery of the expansion rack",
  0x3932: "BAF: failure of backup voltage on expansion rack",
  0x3933: "24 volt supply failure on at least one expansion rack",
  0x3942: "Module error",
  0x3951: "PROFINET IO submodule removed",
  0x3954: "PROFINET IO interface submodule/submodule removed",
  0x3961: "Module/interface module removed, cannot be addressed",
  0x3966: "Module cannot be addressed, load voltage error",
  0x3968: "Module reconfiguration has ended with error",
  0x3984: "Interface module removed",
  0x3981: "Interface error entering state",
  0x3986: "Performance of an H-Sync link negatively affected",
  0x39B1: "I/O access error when updating the process image input table",
  0x39B2: "I/O access error when transferring the process image to the output modules",
  0x39B3: "I/O access error when updating the process image input table",
  0x39B4: "I/O access error when transferring the process image to the output modules",
  0x39C1: "Expansion rack failure (1 to 21), entering state",
  0x39C3: "Distributed I/Os: master system failure entering state",
  0x39C4: "Distributed I/Os: station failure, entering state",
  0x39C5: "Distributed I/Os: station fault, entering state",
  0x39CA: "PROFINET IO system failure",
  0x39CB: "PROFINET IO station failure",
  0x39CC: "PROFINET IO station error",
  0x39CD: "PROFINET IO station operational again, but expected configuration does not match actual configuration",
  0x39CE: "PROFINET IO station operational again, but error(s) in module parameter assignment",
  0x42F3: "Checksum error detected and corrected by the operating system",
  0x42F4: "Standby CPU: connection/update via SFC90 is locked in the master CPU",
  0x4300: "Backed-up power on",
  0x4301: "Mode transition from STOP to STARTUP",
  0x4302: "Mode transition from STARTUP to RUN",
  0x4303: "STOP caused by stop switch being activated",
  0x4304: "STOP caused by PG STOP operation or by SFB 20 STOP",
  0x4305: "HOLD: breakpoint reached",
  0x4306: "HOLD: breakpoint exited",
  0x4307: "Memory reset started by PG operation",
  0x4308: "Memory reset started by switch setting",
  0x4309: "Memory reset started automatically (power on not backed up)",
  0x430A: "HOLD exited, transition to STOP",
  0x430D: "STOP caused by other CPU in multicomputing",
  0x430E: "Memory reset executed",
  0x430F: "STOP on the module due to STOP on a CPU",
  0x4318: "Start of CiR",
  0x4319: "CiR completed",
  0x4357: "Module watchdog started",
  0x4358: "All modules are ready for operation",
  0x43B0: "Firmware update was successful",
  0x43B4: "Error in firmware fuse",
  0x43B6: "Firmware updates canceled by redundant modules",
  0x43D3: "STOP on standby CPU",
  0x43DC: "Abort during link-up with switchover",
  0x43DE: "Updating aborted due to monitoring time being exceeded during the n-th attempt, new update attempt initiated",
  0x43DF: "Updating aborted for final time due to monitoring time being exceeded after completing the maximum amount of attempts. User intervention required",
  0x43E0: "Change from solo mode after link-up",
  0x43E1: "Change from link-up after updating",
  0x43E2: "Change from updating to redundant mode",
  0x43E3: "Master CPU: change from redundant mode to solo mode",
  0x43E4: "Standby CPU: change from redundant mode after error-search mode",
  0x43E5: "Standby CPU: change from error-search mode after link-up or STOP",
  0x43E6: "Link-up aborted on the standby CPU",
  0x43E7: "Updating aborted on the standby CPU",
  0x43E8: "Standby CPU: change from link-up after startup",
  0x43E9: "Standby CPU: change from startup after updating",
  0x43F1: "Reserve-master switchover",
  0x43F2: "Coupling of incompatible H-CPUs blocked by system program",
  0x4510: "STOP violation of the CPU's data range",
  0x4520: "DEFECTIVE: STOP not possible",
  0x4521: "DEFECTIVE: failure of instruction processing processor",
  0x4522: "DEFECTIVE: failure of clock chip",
  0x4523: "DEFECTIVE: failure of clock pulse generator",
  0x4524: "DEFECTIVE: failure of timer update function",
  0x4525: "DEFECTIVE: failure of multicomputing synchronization",
  0x4527: "DEFECTIVE: failure of I/O access monitoring",
  0x4528: "DEFECTIVE: failure of scan time monitoring",
  0x4530: "DEFECTIVE: memory test error in internal memory",
  0x4532: "DEFECTIVE: failure of core resources",
  0x4536: "DEFECTIVE: switch defective",
  0x4540: "STOP: Memory expansion of the internal work memory has gaps. First memory expansion too small or missing",
  0x4541: "STOP caused by priority class system",
  0x4542: "STOP caused by object management system",
  0x4543: "STOP caused by test functions",
  0x4544: "STOP caused by diagnostic system",
  0x4545: "STOP caused by communication system",
  0x4546: "STOP caused by CPU memory management",
  0x4547: "STOP caused by process image management",
  0x4548: "STOP caused by I/O management",
  0x454A: "STOP caused by configuration: an OB deselected with STEP 7 was being loaded into the CPU during STARTUP",
  0x4550: "DEFECTIVE: internal system error",
  0x4555: "No restart possible, monitoring time elapsed",
  0x4556: "STOP: memory reset request from communication system / due to data inconsistency",
  0x4562: "STOP caused by programming error (OB not loaded or not possible)",
  0x4563: "STOP caused by I/O access error (OB not loaded or not possible)",
  0x4567: "STOP caused by H event",
  0x4568: "STOP caused by time error (OB not loaded or not possible)",
  0x456A: "STOP caused by diagnostic interrupt (OB not loaded or not possible)",
  0x456B: "STOP caused by removing/inserting module (OB not loaded or not possible)",
  0x456C: "STOP caused by CPU hardware error (OB not loaded or not possible, or no FRB)",
  0x456D: "STOP caused by program sequence error (OB not loaded or not possible)",
  0x456E: "STOP caused by communication error (OB not loaded or not possible)",
  0x456F: "STOP caused by rack failure OB (OB not loaded or not possible)",
  0x4570: "STOP caused by process interrupt (OB not loaded or not possible)",
  0x4571: "STOP caused by nesting stack error",
  0x4572: "STOP caused by master control relay stack error",
  0x4573: "STOP caused by exceeding the nesting depth for synchronous errors",
  0x4574: "STOP caused by exceeding interrupt stack nesting depth in the priority class stack",
  0x4575: "STOP caused by exceeding block stack nesting depth in the priority class stack",
  0x4576: "STOP caused by error when allocating the local data",
  0x4578: "STOP caused by unknown opcode",
  0x457A: "STOP caused by code length error",
  0x457B: "STOP caused by DB not being loaded on on-board I/Os",
  0x457D: "Reset/clear request because the version of the internal interface to the integrated technology was changed",
  0x457F: "STOP caused by STOP command",
  0x4580: "STOP: back-up buffer contents inconsistent (no transition to RUN)",
  0x4590: "STOP caused by overloading the internal functions",
  0x45D5: "LINK-UP rejected due to mismatched CPU memory configuration of the sub-PLC",
  0x45D6: "LINK-UP rejected due to mismatched system program of the sub-PLC",
  0x45D8: "DEFECTIVE: hardware fault detected due to other error",
  0x45D9: "STOP due to SYNC module error",
  0x45DA: "STOP due to synchronization error between H CPUs",
  0x45DD: "LINK-UP rejected due to running test or other online functions",
  0x4926: "DEFECTIVE: failure of the watchdog for I/O access",
  0x4931: "STOP or DEFECTIVE: memory test error in memory submodule",
  0x4933: "Checksum error",
  0x4934: "DEFECTIVE: memory not available",
  0x4935: "DEFECTIVE: cancelled by watchdog/processor exceptions",
  0x4949: "STOP caused by continuous hardware interrupt",
  0x494D: "STOP caused by I/O error",
  0x494E: "STOP caused by power failure",
  0x494F: "STOP caused by configuration error",
  0x4959: "One or more modules not ready for operation",
  0x497C: "STOP caused by integrated technology",
  0x49A0: "STOP caused by parameter assignment error or non-permissible variation of setpoint and actual extension: Start-up blocked",
  0x49A1: "STOP caused by parameter assignment error: memory reset request",
  0x49A2: "STOP caused by error in parameter modification: startup disabled",
  0x49A3: "STOP caused by error in parameter modification: memory reset request",
  0x49A4: "STOP: inconsistency in configuration data",
  0x49A5: "STOP: distributed I/Os: inconsistency in the loaded configuration information",
  0x49A6: "STOP: distributed I/Os: invalid configuration information",
  0x49A7: "STOP: distributed I/Os: no configuration information",
  0x49A8: "STOP: error indicated by the interface module for the distributed I/Os",
  0x49B1: "Firmware update data incorrect",
  0x49B2: "Firmware update: hardware version does not match firmware",
  0x49B3: "Firmware update: module type does not match firmware",
  0x49D0: "LINK-UP aborted due to violation of coordination rules",
  0x49D1: "LINK-UP/UPDATE sequence aborted",
  0x49D2: "Standby CPU changed to STOP due to STOP on the master CPU during link-up",
  0x49D4: "STOP on a master, since partner CPU is also a master (link-up error)",
  0x49D7: "LINK-UP rejected due to change in user program or in configuration",
  0x510F: "A problem as occurred with WinLC. This problem has caused the CPU to go into STOP mode or has caused a fault in the CPU",
  0x530D: "New startup information in the STOP mode",
  0x5311: "Startup despite Not Ready message from module(s)",
  0x5371: "Distributed I/Os: end of the synchronization with a DP master",
  0x5380: "Diagnostic buffer entries of interrupt and asynchronous errors disabled",
  0x5395: "Distributed I/Os: reset of a DP master",
  0x53A2: "Download of technology firmware successful",
  0x53A4: "Download of technology DB not successful",
  0x53FF: "Reset to factory setting",
  0x5445: "Start of System reconfiguration in RUN mode",
  0x5481: "All licenses for runtime software are complete again",
  0x5498: "No more inconsistency with DP master systems due to CiR",
  0x5545: "Start of System reconfiguration in RUN mode",
  0x5581: "One or several licenses for runtime software are missing",
  0x558A: "Difference between the MLFB of the configured and inserted CPU",
  0x558B: "Difference in the firmware version of the configured and inserted CPU",
  0x5598: "Start of possible inconsistency with DP master systems due to CiR",
  0x55A5: "Version conflict: internal interface with integrated technology",
  0x55A6: "The maximum number of technology objects has been exceeded",
  0x55A7: "A technology DB of this type is already present",
  0x5879: "Diagnostic message from DP interface: EXTF LED off",
  0x5960: "Parameter assignment error when switching",
  0x5961: "Parameter assignment error",
  0x5962: "Parameter assignment error preventing startup",
  0x5963: "Parameter assignment error with memory reset request",
  0x5966: "Parameter assignment error when switching",
  0x5969: "Parameter assignment error with startup blocked",
  0x596A: "PROFINET IO: IP address of an IO device already present",
  0x596B: "IP address of an Ethernet interface already exists",
  0x596C: "Name of an Ethernet interface already exists",
  0x596D: "The existing network configuration does not mach the system requirements or configuration",
  0x5979: "Diagnostic message from DP interface: EXTF LED on",
  0x597C: "DP Global Control command failed or moved",
  0x597C: "DP command Global Control failure or moved",
  0x59A0: "The interrupt can not be associated in the CPU",
  0x59A1: "Configuration error in the integrated technology",
  0x59A3: "Error when downloading the integrated technology",
  0x6253: "Firmware update: End of firmware download over the network",
  0x6316: "Interface error when starting programmable controller",
  0x6390: "Formatting of Micro Memory Card complete",
  0x6353: "Firmware update: Start of firmware download over the network",
  0x6500: "Connection ID exists twice on module",
  0x6501: "Connection resources inadequate",
  0x6502: "Error in the connection description",
  0x6510: "CFB structure error detected in instance DB when evaluating EPROM",
  0x6514: "GD packet number exists twice on the module",
  0x6515: "Inconsistent length specifications in GD configuration information",
  0x6521: "No memory submodule and no internal memory available",
  0x6522: "Illegal memory submodule: replace submodule and reset memory",
  0x6523: "Memory reset request due to error accessing submodule",
  0x6524: "Memory reset request due to error in block header",
  0x6526: "Memory reset request due to memory replacement",
  0x6527: "Memory replaced, therefore restart not possible",
  0x6528: "Object handling function in the STOP/HOLD mode, no restart possible",
  0x6529: "No startup possible during the \"load user program\" function",
  0x652A: "No startup because block exists twice in user memory",
  0x652B: "No startup because block is too long for submodule - replace submodule",
  0x652C: "No startup due to illegal OB on submodule",
  0x6532: "No startup because illegal configuration information on submodule",
  0x6533: "Memory reset request because of invalid submodule content",
  0x6534: "No startup: block exists more than once on submodule",
  0x6535: "No startup: not enough memory to transfer block from submodule",
  0x6536: "No startup: submodule contains an illegal block number",
  0x6537: "No startup: submodule contains a block with an illegal length",
  0x6538: "Local data or write-protection ID (for DB) of a block illegal for CPU",
  0x6539: "Illegal command in block (detected by compiler)",
  0x653A: "Memory reset request because local OB data on submodule too short",
  0x6543: "No startup: illegal block type",
  0x6544: "No startup: attribute \"relevant for processing\" illegal",
  0x6545: "Source language illegal",
  0x6546: "Maximum amount of configuration information reached",
  0x6547: "Parameter assignment error assigning parameters to modules (not on P bus, cancel download)",
  0x6548: "Plausibility error during block check",
  0x6549: "Structure error in block",
  0x6550: "A block has an error in the CRC",
  0x6551: "A block has no CRC",
  0x6560: "SCAN overflow",
  0x6805: "Resource problem on configured connections, eliminated",
  0x6881: "Interface error leaving state",
  0x6905: "Resource problem on configured connections",
  0x6981: "Interface error entering state",
  0x72A2: "Failure of a DP master or a DP master system",
  0x72A3: "Redundancy restored on the DP slave",
  0x72DB: "Safety program: safety mode disabled",
  0x72E0: "Loss of redundancy in communication, problem eliminated",
  0x7301: "Loss of redundancy (1 of 2) due to failure of a CPU",
  0x7302: "Loss of redundancy (1 of 2) due to STOP on the standby triggered by user",
  0x7303: "H system (1 of 2) changed to redundant mode",
  0x7323: "Discrepancy found in operating system data",
  0x7331: "Standby-master switchover due to master failure",
  0x7333: "Standby-master switchover due to system modification during runtime",
  0x7334: "Standby-master switchover due to communication error at the synchronization module",
  0x7340: "Synchronization error in user program due to elapsed wait time",
  0x7341: "Synchronization error in user program due to waiting at different synchronization points",
  0x7342: "Synchronization error in operating system due to waiting at different synchronization points",
  0x7343: "Synchronization error in operating system due to elapsed wait time",
  0x7344: "Synchronization error in operating system due to incorrect data",
  0x734A: "The \"Re-enable\" job triggered by SFC 90 \"H_CTRL\" was executed",
  0x73A3: "Loss of redundancy on the DP slave",
  0x73C1: "Update process canceled",
  0x73C2: "Updating aborted due to monitoring time being exceeded during the n-th attempt (1 = n = max. possible number of update attempts after abort due to excessive monitoring time)",
  0x73D8: "Safety mode disabled",
  0x73E0: "Loss of redundancy in communication",
  0x73DB: "Safety program: safety mode enabled",
  0x74DD: "Safety program: Shutdown of a fail-save runtime group disabled",
  0x74DE: "Safety program: Shutdown of the F program disabled",
  0x74DF: "Start of F program initialization",
  0x7520: "Error in RAM comparison",
  0x7521: "Error in comparison of process image output value",
  0x7522: "Error in comparison of memory bits, timers, or counters",
  0x75D1: "Safety program: Internal CPU error",
  0x75D2: "Safety program error: Cycle time time-out",
  0x75D6: "Data corrupted in safety program prior to the output to F I/O",
  0x75D7: "Data corrupted in safety program prior to the output to partner F-CPU",
  0x75D9: "Invalid REAL number in a DB",
  0x75DA: "Safety program: Error in safety data format",
  0x75DC: "Runtime group, internal protocol error",
  0x75DD: "Safety program: Shutdown of a fail-save runtime group enabled",
  0x75DE: "Safety program: Shutdown of the F program enabled",
  0x75DF: "End of F program initialization",
  0x75E1: "Safety program: Error in FB \"F_PLK\" or \"F_PLK_O\" or \"F_CYC_CO\" or \"F_TEST\" or \"F_TESTC\"",
  0x75E2: "Safety program: Area length error",
  0x7852: "SYNC module inserted",
  0x7855: "SYNC module eliminated",
  0x78D3: "Communication error between PROFIsafe and F I/O",
  0x78D4: "Error in safety relevant communication between F CPUs",
  0x78D5: "Error in safety relevant communication between F CPUs",
  0x78E3: "F-I/O device input channel depassivated",
  0x78E4: "F-I/O device output channel depassivated",
  0x78E5: "F-I/O device depassivated",
  0x7934: "Standby-master switchover due to connection problem at the SYNC module",
  0x7950: "Synchronization module missing",
  0x7951: "Change at the SYNC module without Power On",
  0x7952: "SYNC module removed",
  0x7953: "Change at the SYNC-module without reset",
  0x7954: "SYNC module: rack number assigned twice",
  0x7955: "SYNC module error",
  0x7956: "Illegal rack number set on SYNC module",
  0x7960: "Redundant I/O: Time-out of discrepancy time at digital input, error is not yet localized",
  0x7961: "Redundant I/O, digital input error: Signal change after expiration of the discrepancy time",
  0x7962: "Redundant I/O: Digital input error",
  0x796F: "Redundant I/O: The I/O was globally disabled",
  0x7970: "Redundant I/O: Digital output error",
  0x7980: "Redundant I/O: Time-out of discrepancy time at analog input",
  0x7981: "Redundant I/O: Analog input error",
  0x7990: "Redundant I/O: Analog output error",
  0x79D3: "Communication error between PROFIsafe and F I/O",
  0x79D4: "Error in safety relevant communication between F CPUs",
  0x79D5: "Error in safety relevant communication between F CPUs",
  0x79E3: "F-I/O device input channel passivated",
  0x79E4: "F-I/O device output channel passivated",
  0x79E5: "F-I/O device passivated",
  0x79E6: "Inconsistent safety program",
  0x79E7: "Simulation block (F system block) loaded",
}

cpu_diag_eventid_0x8_0x9_names = {
  0x8000: "Module fault/OK",
  0x8001: "Internal error",
  0x8002: "External error",
  0x8003: "Channel error",
  0x8004: "No external auxiliary voltage",
  0x8005: "No front connector",
  0x8006: "No parameter assignment",
  0x8007: "Incorrect parameters in module",
  0x8030: "User submodule incorrect/not found",
  0x8031: "Communication problem",
  0x8032: "Operating mode: RUN/STOP (STOP: entering state, RUN: leaving state)",
  0x8033: "Time monitoring responded (watchdog)",
  0x8034: "Internal module power failure",
  0x8035: "BATTF: battery exhausted",
  0x8036: "Total backup failed",
  0x8040: "Expansion rack failed",
  0x8041: "Processor failure",
  0x8042: "EPROM error",
  0x8043: "RAM error",
  0x8044: "ADC/DAC error",
  0x8045: "Fuse blown",
  0x8046: "Hardware interrupt lost Any",
  0x8050: "Configuration/parameter assignment error",
  0x8051: "Common mode error",
  0x8052: "Short circuit to phase",
  0x8053: "Short circuit to ground",
  0x8054: "Wire break",
  0x8055: "Reference channel error",
  0x8056: "Below measuring range",
  0x8057: "Above measuring range Analog input",
  0x8060: "Configuration/parameter assignment error",
  0x8061: "Common mode error",
  0x8062: "Short circuit to phase",
  0x8063: "Short circuit to ground",
  0x8064: "Wire break",
  0x8066: "No load voltage",
  0x8070: "Configuration/parameter assignment error",
  0x8071: "Chassis ground fault",
  0x8072: "Short circuit to phase (sensor)",
  0x8073: "Short circuit to ground (sensor)",
  0x8074: "Wire break",
  0x8075: "No sensor power supply Digital input",
  0x8080: "Configuration/parameter assignment error",
  0x8081: "Chassis ground fault",
  0x8082: "Short circuit to phase",
  0x8083: "Short circuit to ground",
  0x8084: "Wire break",
  0x8085: "Fuse tripped",
  0x8086: "No load voltage",
  0x8087: "Excess temperature Digital output",
  0x80B0: "Counter module, signal A faulty",
  0x80B1: "Counter module, signal B faulty",
  0x80B2: "Counter module, signal N faulty",
  0x80B3: "Counter module, incorrect value passed between the channels",
  0x80B4: "Counter module, 5.2 V sensor supply faulty",
  0x80B5: "Counter module, 24 V sensor supply faulty",
  0x9001: "Automatic/Manual mode (coming=man,going=auto)",
  0x9002: "OPEN/CLOSED, ON/OFF",
  0x9003: "Manual command enable",
  0x9004: "Unit protective command (OPEN/CLOSED)",
  0x9005: "Process enable",
  0x9006: "System protection command",
  0x9007: "Process value monitoring responded",
  0x9008: "Manipulated variable monitoring responded",
  0x9009: "System deviation greater than permitted",
  0x900A: "Limit position error",
  0x900B: "Runtime error",
  0x900C: "Command execution error (sequencer)",
  0x900D: "Operating status running > OPEN",
  0x900E: "Operating status running > CLOSED",
  0x900F: "Command blocking",
  0x9011: "Process status OPEN/ON",
  0x9012: "Process status CLOSED/OFF",
  0x9013: "Process status intermediate position",
  0x9014: "Process status ON via AUTO",
  0x9015: "Process status ON via manual",
  0x9016: "Process status ON via protective command",
  0x9017: "Process status OFF via AUTO",
  0x9018: "Process status OFF via manual",
  0x9019: "Process status OFF via protective command",
  0x9021: "Function error on approach",
  0x9022: "Function error on leaving",
  0x9031: "Actuator (DE/WE) limit position OPEN",
  0x9032: "Actuator (DE/WE) limit position not OPEN",
  0x9033: "Actuator (DE/WE) limit position CLOSED",
  0x9034: "Actuator (DE/WE) limit position not CLOSED",
  0x9041: "Illegal status, tolerance time elapsed",
  0x9042: "Illegal status, tolerance time not elapsed",
  0x9043: "Interlock error, tolerance time = 0",
  0x9044: "Interlock error, tolerance time > 0",
  0x9045: "No reaction",
  0x9046: "Final status exited illegally, tolerance time = 0",
  0x9047: "Final status exited illegally, tolerance time > 0",
  0x9050: "Upper limit of signal range USR",
  0x9051: "Upper limit of measuring range UMR",
  0x9052: "Lower limit of signal range LSR",
  0x9053: "Lower limit of measuring range LMR",
  0x9054: "Upper alarm limit UAL",
  0x9055: "Upper warning limit UWL",
  0x9056: "Upper tolerance limit UTL",
  0x9057: "Lower tolerance limit LTL",
  0x9058: "Lower warning limit LWL",
  0x9059: "Lower alarm limit LAL",
  0x9060: "GRAPH7 step entering/leaving",
  0x9061: "GRAPH7 interlock error",
  0x9062: "GRAPH7 execution error",
  0x9063: "GRAPH7 error noted",
  0x9064: "GRAPH7 error acknowledged",
  0x9070: "Trend exceeded in positive direction",
  0x9071: "Trend exceeded in negative direction",
  0x9072: "No reaction",
  0x9073: "Final state exited illegally",
  0x9080: "Limit value exceeded, tolerance time = 0",
  0x9081: "Limit value exceeded, tolerance time > 0",
  0x9082: "Below limit value, tolerance time = 0",
  0x9083: "Below limit value, tolerance time > 0",
  0x9084: "Gradient exceeded, tolerance time = 0",
  0x9085: "Gradient exceeded, tolerance time > 0",
  0x9086: "Below gradient, tolerance time = 0",
  0x9087: "Below gradient, tolerance time > 0",
  0x9090: "User parameter assignment error entering/leaving",
  0x90F0: "Overflow",
  0x90F1: "Underflow",
  0x90F2: "Division by 0",
  0x90F3: "Illegal calculation operation",
}


# Type of alarmquery in alarm query request
alarm_message_querytype_names = {
  1: ( 'S7COMM_ALARM_MESSAGE_QUERYTYPE_BYALARMTYPE', "ByAlarmtype" ),
  3: ( 'S7COMM_ALARM_MESSAGE_QUERYTYPE_BYEVENTID', "ByEventID" ),
}

# Alarmtype in alarm query
alarm_message_query_alarmtype_names = {
  1: ( 'S7COMM_ALARM_MESSAGE_QUERY_ALARMTYPE_SCAN', "SCAN" ),
  2: ( 'S7COMM_ALARM_MESSAGE_QUERY_ALARMTYPE_ALARM_8', "ALARM_8" ),
  4: ( 'S7COMM_ALARM_MESSAGE_QUERY_ALARMTYPE_ALARM_S', "ALARM_S" ),
}

'''

/* CPU message service */
static gint hf_s7comm_cpu_msgservice_subscribe_events = -1;
static gint hf_s7comm_cpu_msgservice_subscribe_events_modetrans = -1;
static gint hf_s7comm_cpu_msgservice_subscribe_events_system = -1;
static gint hf_s7comm_cpu_msgservice_subscribe_events_userdefined = -1;
static gint hf_s7comm_cpu_msgservice_subscribe_events_alarms = -1;
static gint ett_s7comm_cpu_msgservice_subscribe_events = -1;
static const int *s7comm_cpu_msgservice_subscribe_events_fields[] = {
    &hf_s7comm_cpu_msgservice_subscribe_events_modetrans,
    &hf_s7comm_cpu_msgservice_subscribe_events_system,
    &hf_s7comm_cpu_msgservice_subscribe_events_userdefined,
    &hf_s7comm_cpu_msgservice_subscribe_events_alarms,
    NULL
};
static gint hf_s7comm_cpu_msgservice_req_reserved1 = -1;
static gint hf_s7comm_cpu_msgservice_username = -1;
static gint hf_s7comm_cpu_msgservice_almtype = -1;
static gint hf_s7comm_cpu_msgservice_req_reserved2 = -1;
static gint hf_s7comm_cpu_msgservice_res_result = -1;
static gint hf_s7comm_cpu_msgservice_res_reserved1 = -1;
static gint hf_s7comm_cpu_msgservice_res_reserved2 = -1;
static gint hf_s7comm_cpu_msgservice_res_reserved3 = -1;

'''

# Function codes in parameter part
S7COMM_SERV_CPU = 0x00
S7COMM_SERV_SETUPCOMM = 0xF0
S7COMM_SERV_READVAR = 0x04
S7COMM_SERV_WRITEVAR = 0x05
S7COMM_FUNCREQUESTDOWNLOAD = 0x1A
S7COMM_FUNCDOWNLOADBLOCK = 0x1B
S7COMM_FUNCDOWNLOADENDED = 0x1C
S7COMM_FUNCSTARTUPLOAD = 0x1D
S7COMM_FUNCUPLOAD = 0x1E
S7COMM_FUNCENDUPLOAD = 0x1F
S7COMM_FUNCPISERVICE = 0x28
S7COMM_FUNC_PLC_STOP = 0x29

param_functionnames = {
  0x00: ( 'S7COMM_SERV_CPU', "CPU services" ),
  0xF0: ( 'S7COMM_SERV_SETUPCOMM', "Setup communication" ),
  0x04: ( 'S7COMM_SERV_READVAR', "Read Var" ),
  0x05: ( 'S7COMM_SERV_WRITEVAR', "Write Var" ),
  0x1A: ( 'S7COMM_FUNCREQUESTDOWNLOAD', "Request download" ),
  0x1B: ( 'S7COMM_FUNCDOWNLOADBLOCK', "Download block" ),
  0x1C: ( 'S7COMM_FUNCDOWNLOADENDED', "Download ended" ),
  0x1D: ( 'S7COMM_FUNCSTARTUPLOAD', "Start upload" ),
  0x1E: ( 'S7COMM_FUNCUPLOAD', "Upload" ),
  0x1F: ( 'S7COMM_FUNCENDUPLOAD', "End upload" ),
  0x28: ( 'S7COMM_FUNCPISERVICE', "PI-Service" ),
  0x29: ( 'S7COMM_FUNC_PLC_STOP', "PLC Stop" ),
}

cpu_msgservice_almtype_names = {
  0: "SCAN_ABORT",
  1: "SCAN_INITIATE",
  4: "ALARM_ABORT",
  5: "ALARM_INITIATE",
  8: "ALARM_S_ABORT",
  9: "ALARM_S_INITIATE",
}

# static gint hf_s7comm_modetrans_param_subfunc = -1;

modetrans_param_subfunc_names = {
  0: "STOP",
  1: "Warm Restart",
  2: "RUN",
  3: "Hot Restart",
  4: "HOLD",
  6: "Cold Restart",
  9: "RUN_R (H-System redundant)",
  11: "LINK-UP",
  12: "UPDATE",
}

'''
/* These are the ids of the subtrees that we are creating */
static gint ett_s7comm = -1;                                        /* S7 communication tree, parent of all other subtree */
static gint ett_s7comm_header = -1;                                 /* Subtree for header block */
static gint ett_s7comm_param = -1;                                  /* Subtree for parameter block */
static gint ett_s7comm_param_item = -1;                             /* Subtree for items in parameter block */
static gint ett_s7comm_param_subitem = -1;                          /* Subtree for subitems under items in parameter block */
static gint ett_s7comm_data = -1;                                   /* Subtree for data block */
static gint ett_s7comm_data_item = -1;                              /* Subtree for an item in data block */
static gint ett_s7comm_item_address = -1;                           /* Subtree for an address (byte/bit) */
static gint ett_s7comm_cpu_alarm_message = -1;                      /* Subtree for an alarm message */
static gint ett_s7comm_cpu_alarm_message_object = -1;               /* Subtree for an alarm message block*/
static gint ett_s7comm_cpu_alarm_message_timestamp = -1;            /* Subtree for an alarm message timestamp */
static gint ett_s7comm_cpu_alarm_message_associated_value = -1;     # Subtree for an alarm message associated value */
static gint ett_s7comm_cpu_diag_msg = -1;                           # Subtree for a CPU diagnostic message
'''

mon_names = ( "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" );




# Names of types in userdata parameter part
S7_USERDATA_TYPES_PARAMETER_PART_NAMES = {
  0x00 : 'S7COMM_UD_TYPE_PUSH',
  0x04 : 'S7COMM_UD_TYPE_REQ',
  0x08 : 'S7COMM_UD_TYPE_RES',
}

S7_PDU_TYPE = {
  0x0 : "?",
  0x1 : "ED Expedited Data",
  0x2 : "EA Expedited Data Acknowledgement",
  0x4 : "UD",
  0x5 : "RJ Reject",
  0x6 : "AK Data Acknowledgement",
  0x7 : "ER TPDU Error",
  0x8 : "DR Disconnect Request",
  0xC : "DC Disconnect Confirm",
  0xD : "CC Connect Confirm",
  0xE : "CR Connect Request",
  0xF : "DT Data",
  224 : "CR Connect Request",
}
# 0x01 : 'Connection init',
# 0x02 : 'Data transfer',

S7_PACKET_TYPE = {
    2    : '?',
    17   : '?',
    0x31 : 'Request',
    0x32 : 'Response',
    0x33 : 'Keep-alive or cyclic',
}

S7_FUNCTION_CODE = {
    0      : '?',
    0x04ca : 'Connect. Init session',
    0x0542 : 'Write ?',
    0x0586 : '?',
    0x054c : 'Read ?',
    0x0524 : '?',
    0x006a : '?',
    0x04bb : '?',
    0x0017 : '?',        
    4676   : '?',
    12801  : '?',
    12803  : '?',
    12807  : '?'
}
# ----------------------------------------

class S7Packet(object):
    S7COMM_MIN_TELEGRAM_LENGTH=10 # Min. telegram length for heuristic check
    S7COMM_PROT_ID=0x32 # Protocol identifier
    S7COMM_ROSCTR_JOB = 0x01
    S7COMM_ROSCTR_ACK = 0x02
    S7COMM_ROSCTR_ACK_DATA = 0x03
    S7COMM_ROSCTR_USERDATA = 0x07

    def __init__(self, payload):
        if len(payload) < S7Packet.S7COMM_MIN_TELEGRAM_LENGTH:
            raise ValueError('payload length is too small ({} bytes < {})'.format(len(payload), S7Packet.S7COMM_MIN_TELEGRAM_LENGTH))
        self.hp = payload.decode('hex') # as normal hex values
        self.pp = {0: ('field_name', 'value', 'default comment', 0)}
        # BEGIN S7 HEADER:
        self.header_protid=unp('!B', self.hp[0:1])[0]
        self._add_field('Protocol ID', self.header_protid, 'Protocol ID', 1)
        self.header_rosctr=unp('!B', self.hp[1:2])[0]
	self._add_field('ROSCTR', rosctr_names[self.header_rosctr], 'ROSCTR (Remote Operating Service Control) - PDU Type', 1)
        # Header size= 10 Bytes, execpt when type 2 or 3 (response) -> 12 Bytes
        if ( 2<= self.header_rosctr <= 3):
          # When type 2 or 3 (response) -> 12 Bytes
          self.hlength=12
        else:
          # Defaults to 10 bytes
          self.hlength=10
        if not ( ( self.S7COMM_PROT_ID == self.header_protid ) and ( 0x01 <= self.header_rosctr <= 0x07 ) ):
          # Not a S7 packet
          raise ValueError("payload doesn't seems to be a S7comm packet")
        # Redundancy Identification (Reserved)
        self.header_redid=unp('!H', self.hp[2:4])[0]
        # Protocol Data Unit Reference
        self.header_pduref=unp('!H', self.hp[4:6])[0]
	self._add_field('PDUREF', self.header_pduref, 'Packet Data Unit Reference', 1)
        # Parameter length
        self.header_parlg=unp('!H', self.hp[6:8])[0]
        # Data length
        self.header_datalg=unp('!H', self.hp[8:10])[0]
        # Only available at type 2 or 3 :
        if ( 2<= self.header_rosctr <= 3):
          self.header_errcls=unp('!B', self.hp[10:11])[0]
          self.header_errcod=unp('!B', self.hp[11:12])[0]
        else:
          self.header_errcls=-1
          self.header_errcod=-1
        # END Header
        # BEGIN PARAMETER:
        if self.header_errcls > 0 or self.header_errcod > 0:
          # when there is an error, init the errorcode of the parameterpart from the header
          self.param_errcod=unp('!H', self.hp[10:12])[0]
        else:
          self.param_errcod=-1
        self.param_service=-1
        self.param_itemcount = -1
        self.param_data = -1
        self.param_neg_pdu_length = -1
        self.param_setup_reserved1 = -1
        self.param_maxamq_calling = -1
        self.param_maxamq_called = -1
        # END PARAMETER
	# BEGIN ITEM DATA
	self.param_item = -1
	self.param_subitem = -1		# Substructure
	self.item_varspec = -1		# Variable specification 
	self.item_varspec_length = -1	# Length of following address specification
	self.item_syntax_id = -1	# Syntax Id
	self.item_transport_size = -1	# Transport size, 1 Byte
	self.item_length = -1		# length, 2 Bytes
	self.item_db = -1		# DB/M/E/A, 2 Bytes
	self.item_area = -1		# Area code, 1 byte
	self.item_address = -1		# Bit address, 3 Bytes
	self.item_address_byte = -1	# address: Byte address
	self.item_address_bit = -1	# address: Bit address
	self.item_address_nr = -1	# address: Timer/Counter/block number
	# Special variable read with Syntax-Id 0xb0 (DBREAD)
	self.item_dbread_numareas = -1	# Number of areas following, 1 Byte
	self.item_dbread_length = -1	# length, 1 Byte
	self.item_dbread_db = -1	# DB number, 2 Bytes
	self.item_dbread_startadr = -1	# Start address, 2 Bytes
	# NCK access with Syntax-Id 0x82
	self.item_nck_areaunit = -1	# Bitmask: aaauuuuu: a=area, u=unit
	self.item_nck_area = -1	
	self.item_nck_unit = -1
	self.item_nck_column = -1
	self.item_nck_line = -1
	self.item_nck_module = -1
	self.item_nck_linecount = -1

	self.data_returncode = -1                 # return code, 1 byte
	self.data_transport_size = -1             # transport size 1 byte
	self.data_length = -1                     # Length of data, 2 Bytes

	self.data_item = -1

	self.readresponse_data = -1
	self.data_fillbyte = -1
	# END ITEM DATA

	# timefunction: s7 timestamp
	self.data_ts = -1
	self.data_ts_reserved = -1
	self.data_ts_year1 = -1                   # first byte of BCD coded year, should be ignored
	self.data_ts_year2 = -1                   # second byte of BCD coded year, if 00...89 then it's 2000...2089, else 1990...1999
	self.data_ts_month = -1
	self.data_ts_day = -1
	self.data_ts_hour = -1
	self.data_ts_minute = -1
	self.data_ts_second = -1
	self.data_ts_millisecond = -1
	self.data_ts_weekday = -1

	# userdata, block services
	self.userdata_data = -1

	self.userdata_param_head = -1
	self.userdata_param_len = -1
	self.userdata_param_reqres2 = -1          # unknown
	self.userdata_param_type = -1
	self.userdata_param_funcgroup = -1
	self.userdata_param_subfunc_prog = -1
	self.userdata_param_subfunc_cyclic = -1
	self.userdata_param_subfunc_block = -1
	self.userdata_param_subfunc_cpu = -1
	self.userdata_param_subfunc_sec = -1
	self.userdata_param_subfunc_time = -1
	self.userdata_param_subfunc_ncprg = -1
	self.userdata_param_subfunc = -1          # for all other subfunctions
	self.userdata_param_seq_num = -1
	self.userdata_param_dataunitref = -1
	self.userdata_param_dataunit = -1

	# block functions, list blocks of type
	self.ud_blockinfo_block_type = -1         # Block type, 2 bytes
	self.ud_blockinfo_block_num = -1          # Block number, 2 bytes as int
	self.ud_blockinfo_block_cnt = -1          # Count, 2 bytes as int
	self.ud_blockinfo_block_flags = -1        # Block flags (unknown), 1 byte
	self.ud_blockinfo_block_lang = -1         # Block language, 1 byte, stringlist blocklanguage_names
	# block functions, get block infos
	self.ud_blockinfo_block_num_ascii = -1    # Block number, 5 bytes, ASCII
	self.ud_blockinfo_filesys = -1            # Filesystem, 1 byte, ASCII
	self.ud_blockinfo_res_infolength = -1     # Length of Info, 2 bytes as int
	self.ud_blockinfo_res_unknown2 = -1       # Unknown blockinfo 2, 2 bytes, HEX
	self.ud_blockinfo_res_const3 = -1         # Constant 3, 2 bytes, ASCII
	self.ud_blockinfo_res_unknown = -1        # Unknown byte(s)
	self.ud_blockinfo_subblk_type = -1        # Subblk type, 1 byte, stringlist subblktype_names
	self.ud_blockinfo_load_mem_len = -1       # Length load memory, 4 bytes, int
	self.ud_blockinfo_blocksecurity = -1      # Block Security, 4 bytes, stringlist blocksecurity_names
	self.ud_blockinfo_interface_timestamp = -1# Interface Timestamp, string
	self.ud_blockinfo_code_timestamp = -1     # Code Timestamp, string
	self.ud_blockinfo_ssb_len = -1            # SSB length, 2 bytes, int
	self.ud_blockinfo_add_len = -1            # ADD length, 2 bytes, int
	self.ud_blockinfo_localdata_len = -1      # Length localdata, 2 bytes, int
	self.ud_blockinfo_mc7_len = -1            # Length MC7 code, 2 bytes, int
	self.ud_blockinfo_author = -1             # Author, 8 bytes, ASCII
	self.ud_blockinfo_family = -1             # Family, 8 bytes, ASCII
	self.ud_blockinfo_headername = -1         # Name (Header), 8 bytes, ASCII
	self.ud_blockinfo_headerversion = -1      # Version (Header), 8 bytes, ASCII
	self.ud_blockinfo_checksum = -1           # Block checksum, 2 bytes, HEX
	self.ud_blockinfo_reserved1 = -1          # Reserved 1, 4 bytes, HEX
	self.ud_blockinfo_reserved2 = -1          # Reserved 2, 4 bytes, HEX

	self.userdata_blockinfo_flags = -1        # Some flags in Block info response
	self.userdata_blockinfo_linked = -1       # Some flags in Block info response
	self.userdata_blockinfo_standard_block = -1
	self.userdata_blockinfo_nonretain = -1    # Some flags in Block info response
	self.ett_s7comm_userdata_blockinfo_flags = -1
	# Programmer commands, diagnostic data
	self.diagdata_req_askheadersize = -1      # Ask header size, 2 bytes as int
	self.diagdata_req_asksize = -1            # Ask size, 2 bytes as int
	self.diagdata_req_unknown = -1            # for all unknown bytes
	self.diagdata_req_answersize = -1         # Answer size, 2 bytes as int
	self.diagdata_req_block_type = -1         # Block type, 1 byte, stringlist subblktype_names
	self.diagdata_req_block_num = -1          # Block number, 2 bytes as int
	self.diagdata_req_startaddr_awl = -1      # Start address AWL, 2 bytes as int
	self.diagdata_req_saz = -1                # Step address counter (SAZ), 2 bytes as int
	self.diagdata_req_number_of_lines = -1    # Number of lines, 1 byte as int
	self.diagdata_req_line_address = -1       # Address, 2 bytes as int

	# Flags for requested registers in diagnostic data telegrams
	self.diagdata_registerflag = -1           # Registerflags
	self.diagdata_registerflag_stw = -1       # STW = Status word
	self.diagdata_registerflag_accu1 = -1     # Accumulator 1
	self.diagdata_registerflag_accu2 = -1     # Accumulator 2
	self.diagdata_registerflag_ar1 = -1       # Addressregister 1
	self.diagdata_registerflag_ar2 = -1       # Addressregister 2
	self.diagdata_registerflag_db1 = -1       # Datablock register 1
	self.diagdata_registerflag_db2 = -1       # Datablock register 2
	self.ett_s7comm_diagdata_registerflag = -1

	if self.header_rosctr == S7Packet.S7COMM_ROSCTR_JOB or self.header_rosctr == S7Packet.S7COMM_ROSCTR_ACK_DATA:
	  self._s7comm_decode_req_resp()
	elif self.header_rosctr == S7Packet.S7COMM_ROSCTR_USERDATA:
	  self._s7comm_decode_ud()
	# XXX
        self._parse_payload()

    def _s7comm_decode_ud(self):
	# XXX
	return

    def _s7comm_decode_req_resp(self):
	# XXX
        # BEGIN PARAMETER:
	offset = self.hlength
	# XXX PRINT ME
        self.param_service = unp('!B', self.hp[offset:offset+1])[0]
	offset+=1
        self._add_field('Function', param_functionnames[self.param_service], 'Service / Function name', 1)
	return
	if self.header_rosctr == S7Packet.S7COMM_ROSCTR_JOB:
	  if self.param_service == S7COMM_SERV_READVAR or self.param_service == S7COMM_SERV_WRITEVAR:
            self.param_itemcount = unp('!B', self.hp[offset:offset+1])[0]
	    offset+=1
            for i in range(self.param_itemcount):
              offset_old = offset
              offset = self._s7comm_decode_param_item(offset, i)
	      for_len = offset - offset_old
	      if ((for_len % 2) and (i < self.param_itemcount)):
	        offset += 1
	      
        self.param_itemcount = -1
        self.param_data = -1
        self.param_neg_pdu_length = -1
        self.param_setup_reserved1 = -1
        self.param_maxamq_calling = -1
        self.param_maxamq_called = -1
        # END PARAMETER

    def _s7comm_decode_param_item(self, offset, i):
	# TODO
	return 

    def _add_field(self, name, value, comment='default comment', fsize=0):
        indx = max(self.pp.keys())+1
        self.pp[indx] = (name, value, comment, fsize)

    def _shift_hp_data_left(self, hp):
        return hp[sum(map(lambda i: i[3], self.pp.values())) : ]

    def _parse_payload(self):
        hp = deepcopy(self.hp)
        # Get the type byte and deduce hlength
        self.protocol_id = unp('!B', self.hp[0:1])[0]
        self.rosctr = unp('!B', self.hp[1:2])[0]
        if ( 2<= self.rosctr <= 3):
            hlength=12 # Header 10 Bytes, when type 2 or 3 (response) -> 12 Bytes 
        #print "ROSCTR={}".format(rosctr_names[self.rosctr])
        return


        if len(hp[:5]) < 5:
          return
        print "premier: {}".format(unp('!BBHB', hp[:5]))
        header, pdu_type, data_len, packet_type = unp('!BBHB', hp[:5])
        self._add_field('packet header', header, 's7 packet header', 1)
        self._add_field('pdu type', pdu_type, 'PDU type: '+ S7_PDU_TYPE[int(pdu_type)], 1)
        self._add_field('data len', data_len, 'data from next byte minus last 4 bytes', 2)
        self._add_field('packet type', packet_type, 'packet type: '+ S7_PACKET_TYPE[int(packet_type)], 1)
        hp = self._shift_hp_data_left(self.hp)
	return
        
        #hp = hp[5:] # FIX IT EVERY TIME AFTER PARSNG NEW FIELD

        if len(hp[:6]) < 6:
          return
        print "second: {}".format(unp('!HHH', hp[:6]))
        reserved1, function_code, reserved2 = unp('!HHH', hp[:6])
        self._add_field('reserved', reserved1, 'reserved?', 2)
        self._add_field('function code', function_code, 'function code: ' + S7_FUNCTION_CODE[int(function_code)], 2)
        hp = self._shift_hp_data_left(self.hp)
        self._add_field('reserved', reserved2, 'reserved?', 2)
        hp = self._shift_hp_data_left(self.hp)

        if len(hp[:2]) < 2:
          return
        print "troisieme: {}".format( unp('!H', hp[:2]))
        data_sequence_number, = unp('!H', hp[:2])
        self._add_field('data seq numb', data_sequence_number, 'data sequnce number ?', 2)
        hp = self._shift_hp_data_left(self.hp)
      
        # process unknow data and packet footer
        print "quatrieme: {}".format( unp('!%dB' % len(hp[:-4]), hp[:-4]))
        unparsed = unp('!%dB' % len(hp[:-4]), hp[:-4])
        self._add_field('unparsed', unparsed, 'unparsed/unknown data', len(unparsed))
        footer = unp('!I', hp[-4:])[0]
        self._add_field('packet footer', footer, 'packet footer with pdu type', 4)

    def print_packet(self):
        #print "{0:10} : {1:100} : {2:40}".format('FNAME', 'VALUE', 'COMMENT')
        del self.pp[0] # just remove init value
        
        for indx in sorted(self.pp.iterkeys()):
            field_name = self.pp[indx][0]
            field_value = self.pp[indx][1]
            field_comment = self.pp[indx][2]
            print "{0:10} : {1:100} : {2:40}".format( field_name, field_value, field_comment )
        #print ""
        
filename="4-S7comm-Download-DB1-with-password-request.pcap"

for ts, pkt in dpkt.pcap.Reader(open(filename,'r')):
  eth=dpkt.ethernet.Ethernet(pkt) 
  if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
    continue

  ip=eth.data
  if ip.p==dpkt.ip.IP_PROTO_UDP:
    continue
  if ip.p==dpkt.ip.IP_PROTO_TCP: 
    tcp=ip.data
    if tcp.flags & dpkt.tcp.TH_PUSH != 0:
      if tcp.dport == 102 or tcp.sport == 102:
        #s7p=S7Packet(tcp.data.encode('hex'))
        tpkt=dpkt.tpkt.TPKT(tcp.data)
        #s7p=S7Packet(tpkt.data.encode('hex'))
        cotp=tpkt.data
        cotp_size=unp('!B', cotp[:1])[0]+1
        s7_data=cotp[cotp_size:]
        try:
          s7p=S7Packet(s7_data.encode('hex'))
          s7p.print_packet()
        except ValueError as e:
          e_type='Unknown'
          if isinstance(e, ValueError):
            e_type='ValueError'
            continue
          elif isinstance(e, KeyError):
            e_type='KeyError'
          print "** Exception [{}]: {}".format(e_type, e)
