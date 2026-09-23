using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using NetFlow.Domain;

namespace NetFlow.Probes;

/// <summary>RDP 协商结果。</summary>
public sealed record RdpNegotiateResult
{
    public byte ProtocolSelected { get; init; }
    public byte? NegType { get; init; }
    public string SelectedText => ProtocolSelected switch
    {
        0 => "标准 RDP 安全层",
        1 => "TLS",
        2 => "CredSSP/NLA",
        _ => $"0x{ProtocolSelected:X}",
    };
}

/// <summary>
/// RDP 探针（设计文档 4.4）：TCP 3389 + X.224 连接请求/确认（最小化服务握手）。
/// 不声称登录或授权成功。
/// </summary>
public sealed class RdpProbe : TcpHandshakeProbeBase
{
    public override ProbeType Type => ProbeType.Rdp;

    public override string DisplayName => "RDP";

    public async Task<ProbeRun> ExecuteAsync(IPAddress target, int port, ProbeRequest request)
    {
        var run = NewRun(request);
        var timeout = request.Parameters.Timeout;
        var ct = request.CancellationToken;
        run.ResolvedAddresses = [target.ToString()];
        run.AddObservation(Observation.Now($"RDP 探测：{target}:{port}", DisplayName));

        Socket? socket = null;
        try
        {
            socket = await ConnectAsync(target, port, request.SourceAddress, timeout, ct, run, DisplayName)
                .ConfigureAwait(false);
            run.Transport = TransportOutcome.Success;

            // X.224 CR（Connection Request）+ RDP 协商请求（PROTOCOL_SSL | PROTOCOL_HYBRID）
            var cr = BuildConnectionRequest();
            await SendAsync(socket, cr, ct).ConfigureAwait(false);
            run.AddObservation(Observation.Now(
                "发送 X.224 Connection Request（RDP 协商：请求 TLS/CredSSP）", DisplayName));

            var cc = await ReadX224ConfirmAsync(socket, timeout, ct).ConfigureAwait(false);
            // CC TPDU: [0]=3 (TPKT version) [1]=0, [2..3]=len, [4]=lenIndicator, [5]=0xD0 (CC)
            // 协商响应位于 CC 之后的 RDP 负token
            var result = ParseConfirm(cc);
            run.Protocol = ProtocolOutcome.Success;
            run.ProtocolDetail =
                $"X.224 连接确认收到。协商安全层：{result.SelectedText}。" +
                "此为最小化握手成功，不代表登录或授权成功。";
            run.AddObservation(Observation.Now(run.ProtocolDetail, DisplayName));

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

    /// <summary>构造 X.224 CR + RDP_NEG_REQ（类 0，请求 TLS 1 | HYBRID 2）。</summary>
    public static byte[] BuildConnectionRequest()
    {
        // TPKT: 03 00 <len16>，X.224: <LI> E0 0000 0000 <class0>，cookie，RDP_NEG_REQ
        var cookie = Encoding.ASCII.GetBytes(
            $"Cookie: mstshash=netflow\r\n");
        // X.224 长度指示（LI）= CR TPDU 字节数（含协商 token）
        byte x224Len = (byte)(6 + cookie.Length + 8); // 6 头 + cookie + 8 字节 NEG_REQ
        var pkt = new byte[4 + 1 + x224Len];
        pkt[0] = 3; pkt[1] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(pkt.AsSpan(2), (ushort)pkt.Length);
        pkt[4] = x224Len;
        pkt[5] = 0xE0; // CR
        // dst-ref(2) src-ref(2) class(1)=0
        cookie.CopyTo(pkt, 11);
        // RDP_NEG_REQ: type=1, flags=0, length=8, requestedProtocols=3 (TLS|CredSSP)
        int o = 11 + cookie.Length;
        pkt[o] = 1;                       // TYPE_RDP_NEG_REQ
        pkt[o + 1] = 0;                   // flags
        BinaryPrimitives.WriteUInt16LittleEndian(pkt.AsSpan(o + 2), 8); // length
        BinaryPrimitives.WriteUInt32LittleEndian(pkt.AsSpan(o + 4), 3); // requestedProtocols
        return pkt;
    }

    private static async Task<byte[]> ReadX224ConfirmAsync(
        Socket socket, TimeSpan remaining, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(remaining);
        var buf = new byte[64];
        int read = 0;
        while (read < 11) // TPKT4 + X224 至少 7 + NEG token 8
        {
            int n = await socket.ReceiveAsync(buf.AsMemory(read), cts.Token).ConfigureAwait(false);
            if (n == 0) throw new EndOfStreamException("对端在 X.224 确认前关闭连接");
            read += n;
            // 拿到完整 TPKT 后即可退出
            if (read >= 4)
            {
                ushort tpktLen = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(2));
                if (read >= 4 + tpktLen) break;
            }
        }
        return buf[..read];
    }

    public static RdpNegotiateResult ParseConfirm(byte[] data)
    {
        // 扫描 RDP 负 token（type 2 = RESPONSE / type 3 = FAILURE）
        for (int i = 11; i + 4 <= data.Length; i++)
        {
            byte type = data[i];
            if (type is 2 or 3)
            {
                ushort len = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(i + 2));
                if (len == 8)
                {
                    byte selected = type == 2 ? data[i + 4] : (byte)0;
                    return new RdpNegotiateResult { ProtocolSelected = selected, NegType = type };
                }
            }
        }
        // 无协商 token：服务端选择标准 RDP 安全层（旧系统）
        return new RdpNegotiateResult { ProtocolSelected = 0, NegType = null };
    }
}
