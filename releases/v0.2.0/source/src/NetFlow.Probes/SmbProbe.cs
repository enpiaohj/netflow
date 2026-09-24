using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using NetFlow.Domain;

namespace NetFlow.Probes;

/// <summary>SMB 协商结果。</summary>
public sealed record SmbNegotiateResult
{
    public uint NtStatus { get; init; }
    public ushort DialectRevision { get; init; }
    public string StatusText => NtStatus switch
    {
        0x00000000 => "STATUS_SUCCESS",
        0xC00000BB => "STATUS_NOT_SUPPORTED",
        _ => $"0x{NtStatus:X8}",
    };
}

/// <summary>
/// SMB 探针（设计文档 4.4）：TCP 445 与 SMB2 协商。
/// 端口打开不代表共享权限成功 —— 协商成功才说明 SMB 服务可交互。
/// </summary>
public sealed class SmbProbe : TcpHandshakeProbeBase
{
    public override ProbeType Type => ProbeType.Smb;

    public override string DisplayName => "SMB";

    public async Task<ProbeRun> ExecuteAsync(IPAddress target, int port, ProbeRequest request)
    {
        var run = NewRun(request);
        var timeout = request.Parameters.Timeout;
        var ct = request.CancellationToken;
        run.ResolvedAddresses = [target.ToString()];
        run.AddObservation(Observation.Now($"SMB 探测：{target}:{port}", DisplayName));

        Socket? socket = null;
        try
        {
            socket = await ConnectAsync(target, port, request.SourceAddress, timeout, ct, run, DisplayName)
                .ConfigureAwait(false);
            run.Transport = TransportOutcome.Success;

            // —— SMB2 NEGOTIATE（最小化握手）——
            var negotiate = BuildNegotiateRequest();
            await SendAsync(socket, negotiate, ct).ConfigureAwait(false);
            run.AddObservation(Observation.Now(
                $"发送 SMB2 NEGOTIATE（{negotiate.Length} 字节，通告 2.0.2/2.1.0/3.0/3.0.2）",
                DisplayName));

            var resp = await ReadSmb2ResponseAsync(socket, timeout, ct).ConfigureAwait(false);
            var result = ParseNegotiateResponse(resp);
            run.Protocol = result.NtStatus == 0
                ? ProtocolOutcome.Success
                : ProtocolOutcome.ProtocolError;
            run.ProtocolDetail = result.NtStatus == 0
                ? $"SMB 协商成功，选定方言 0x{result.DialectRevision:X4}（{DialectText(result.DialectRevision)}）"
                : $"SMB 协商失败：{result.StatusText}";
            run.AddObservation(Observation.Now(run.ProtocolDetail, DisplayName,
                new Dictionary<string, string>
                {
                    ["ntStatus"] = $"0x{result.NtStatus:X8}",
                    ["dialect"] = $"0x{result.DialectRevision:X4}",
                }));

            FinishRun(run);
            return run;
        }
        catch (Exception ex)
        {
            return HandleTransportException(run, ex, timeout, ct, DisplayName);
        }
        finally
        {
            socket?.Dispose();
        }
    }

    public static string DialectText(ushort dialect) => dialect switch
    {
        0x0202 => "SMB 2.0.2",
        0x0210 => "SMB 2.1.0",
        0x0300 => "SMB 3.0",
        0x0302 => "SMB 3.0.2",
        0x0311 => "SMB 3.1.1",
        _ => $"未知方言 0x{dialect:X4}",
    };

    /// <summary>NetBIOS 会话头 + SMB2 Header(64) + NEGOTIATE Request（MS-SMB2 2.2.3）。</summary>
    public static byte[] BuildNegotiateRequest()
    {
        // 不通告 3.1.1：该方言要求 negotiate contexts（本探针为最小化握手）
        ushort[] dialects = [0x0202, 0x0210, 0x0300, 0x0302];
        const int headerLen = 64;
        int bodyLen = 36 + dialects.Length * 2; // 固定 36 字节 + 方言数组
        int smbLen = headerLen + bodyLen;

        var pkt = new byte[4 + smbLen];
        // NetBIOS 会话头：3 字节大端长度（最高字节 0）
        pkt[1] = (byte)(smbLen >> 16);
        pkt[2] = (byte)(smbLen >> 8);
        pkt[3] = (byte)smbLen;

        // SMB2 Header（偏移以 header 起点计）
        int h = 4;
        pkt[h] = 0xFE; pkt[h + 1] = (byte)'S'; pkt[h + 2] = (byte)'M'; pkt[h + 3] = (byte)'B';
        W16(pkt, h + 4, 64);        // StructureSize
        W16(pkt, h + 6, 0);         // CreditCharge
        W32(pkt, h + 8, 0);         // Status
        W16(pkt, h + 12, 0x0000);   // Command = NEGOTIATE
        W16(pkt, h + 14, 1);        // Credits(Request)
        W32(pkt, h + 16, 0);        // Flags
        W32(pkt, h + 20, 0);        // NextCommand
        W64(pkt, h + 24, 0);        // MessageId（诊断协商取 0）
        // 32..35 Reserved, 36..39 TreeId, 40..47 SessionId, 48..63 Signature 全 0

        // Negotiate Request Body
        int o = h + headerLen;
        W16(pkt, o, 36);                    // StructureSize
        W16(pkt, o + 2, (ushort)dialects.Length); // DialectCount
        W16(pkt, o + 4, 0x0001);            // SecurityMode: signing enabled
        W16(pkt, o + 6, 0);                 // Reserved
        W32(pkt, o + 8, 0);                 // Capabilities
        // o+12..o+27 ClientGuid（全 0 可接受于诊断协商）
        W32(pkt, o + 28, 0);                // NegotiateContextOffset
        W16(pkt, o + 32, 0);                // NegotiateContextCount
        W16(pkt, o + 34, 0);                // Reserved
        int d = o + 36;
        foreach (var dia in dialects)
        {
            W16(pkt, d, dia);
            d += 2;
        }
        return pkt;
    }

    private static void W16(byte[] b, int pos, ushort v)
    {
        b[pos] = (byte)v;
        b[pos + 1] = (byte)(v >> 8);
    }

    private static void W32(byte[] b, int pos, uint v)
    {
        W16(b, pos, (ushort)v);
        W16(b, pos + 2, (ushort)(v >> 16));
    }

    private static void W64(byte[] b, int pos, ulong v)
    {
        W32(b, pos, (uint)v);
        W32(b, pos + 4, (uint)(v >> 32));
    }

    private static async Task<byte[]> ReadSmb2ResponseAsync(
        Socket socket, TimeSpan remaining, CancellationToken ct)
    {
        // 读 NetBIOS 4 字节头
        var header = new byte[4];
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(remaining);
        int read = 0;
        while (read < 4)
        {
            int n = await socket.ReceiveAsync(header.AsMemory(read), cts.Token).ConfigureAwait(false);
            if (n == 0) throw new EndOfStreamException("对端在 SMB2 响应前关闭连接");
            read += n;
        }
        uint len = BinaryPrimitives.ReadUInt32BigEndian(header) & 0x00FFFFFF;
        if (len == 0 || len > 1024 * 1024)
            throw new InvalidOperationException($"SMB2 响应长度异常：{len}");

        var body = new byte[len];
        read = 0;
        while (read < len)
        {
            int n = await socket.ReceiveAsync(body.AsMemory(read), cts.Token).ConfigureAwait(false);
            if (n == 0) throw new EndOfStreamException("对端在 SMB2 响应中关闭连接");
            read += n;
        }
        return body;
    }

    /// <summary>SMB2 响应解析：Header.Status(偏移 8) + Negotiate Response Dialect(偏移 64+2)。</summary>
    public static SmbNegotiateResult ParseNegotiateResponse(byte[] data)
    {
        if (data.Length < 68)
            throw new InvalidOperationException("SMB2 响应过短，非 SMB2 服务");
        uint status = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(8));
        ushort dialect = 0;
        if (data.Length >= 70)
            dialect = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(68));
        return new SmbNegotiateResult { NtStatus = status, DialectRevision = dialect };
    }
}
