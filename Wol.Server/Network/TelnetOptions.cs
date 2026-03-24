namespace Wol.Server.Network;

// Telnet command bytes
public static class Telnet
{
    public const byte IAC  = 0xFF;
    public const byte DONT = 0xFE;
    public const byte DO   = 0xFD;
    public const byte WONT = 0xFC;
    public const byte WILL = 0xFB;
    public const byte SB   = 0xFA; // subnegotiation begin
    public const byte SE   = 0xF0; // subnegotiation end
    public const byte GA   = 0xF9; // go-ahead
    public const byte NOP  = 0xF1;

    // Standard options
    public const byte OPT_ECHO    = 1;
    public const byte OPT_SGA     = 3;  // Suppress Go-Ahead
    public const byte OPT_TTYPE   = 24; // Terminal Type / MTTS
    public const byte OPT_NAWS    = 31; // Negotiate About Window Size
    public const byte OPT_CHARSET = 42; // Character Set

    // MUD-specific options
    public const byte OPT_MSDP  = 69;  // MUD Server Data Protocol
    public const byte OPT_MSSP  = 70;  // MUD Server Status Protocol
    public const byte OPT_MCCP2 = 86;  // MUD Client Compression Protocol v2
    public const byte OPT_MCCP3 = 87;  // MUD Client Compression Protocol v3
    public const byte OPT_GMCP  = 201; // Generic MUD Communication Protocol

    // MSSP byte markers
    public const byte MSSP_VAR = 1;
    public const byte MSSP_VAL = 2;

    // MSDP byte markers
    public const byte MSDP_VAR         = 1;
    public const byte MSDP_VAL         = 2;
    public const byte MSDP_TABLE_OPEN  = 3;
    public const byte MSDP_TABLE_CLOSE = 4;
    public const byte MSDP_ARRAY_OPEN  = 5;
    public const byte MSDP_ARRAY_CLOSE = 6;

    // TTYPE subnegotiation
    public const byte TTYPE_IS   = 0;
    public const byte TTYPE_SEND = 1;

    // CHARSET subnegotiation
    public const byte CHARSET_REQUEST  = 1;
    public const byte CHARSET_ACCEPTED = 2;
    public const byte CHARSET_REJECTED = 3;
}

/// <summary>MTTS capability bitmask flags (sent via TTYPE as "MTTS N").</summary>
[Flags]
public enum MttsFlags : int
{
    None          = 0,
    Ansi          = 1 << 0,
    Vt100         = 1 << 1,
    Utf8          = 1 << 2,
    Color256      = 1 << 3,
    MouseTracking = 1 << 4,
    OscColor      = 1 << 5,
    ScreenReader  = 1 << 6,
    // bit 7 unused
    TrueColor     = 1 << 8,
}

/// <summary>Client capabilities discovered during option negotiation.</summary>
public sealed class ClientCapabilities
{
    public bool SgaActive    { get; set; }
    public bool EchoActive   { get; set; } // server suppressing echo
    public bool Mccp2Active  { get; set; }
    public bool Mccp3Active  { get; set; }
    public bool MsdpActive   { get; set; }
    public bool GmcpActive   { get; set; }

    public int  TerminalCols { get; set; } = 80;
    public int  TerminalRows { get; set; } = 24;

    public string TerminalType { get; set; } = string.Empty;
    public MttsFlags Mtts     { get; set; } = MttsFlags.None;
    public bool CharsetUtf8   { get; set; }

    // MSDP subscribed variables bitmask (mirrors acktng MSDP_BIT_* constants)
    public uint MsdpSubscriptions { get; set; }

    // GMCP subscribed packages bitmask
    public uint GmcpPackages { get; set; }
}
