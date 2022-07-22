package com.wangxc.snmpdemo;

import org.snmp4j.smi.OID;

import java.util.Arrays;

/**
 * @ClassName HwAlarmOidConstant
 * @Description iMAPNorthboundFaultNotification OID
 * @Author wangxc
 * @date 2022/7/22 14:21
 * @Version 1.0
 */
public class HwAlarmOidConstants {

    public static void main(String[] args) {
        OID oid = new OID("1.3.6.1.4.1.2011.2.15.2.4.3.3");
        System.out.println(Arrays.toString(oid.toIntArray()));
    }

    private static final int[] prefixOID = new int[]{1, 3, 6, 1, 4, 1, 2011, 2, 15, 2, 4, 3, 3};

    public static final OID iMAPNorthboundFaultAlarmReportNotificationType = new OID(prefixOID, new int[]{0, 1});

    /**
     * 告警的网络流水号，唯一标识一条告警。
     */
    public static final OID iMAPNorthboundAlarmCSN = new OID(prefixOID, 1);

    /**
     * 告警种类，取值范围如下：
     * 1：故障
     * 2：恢复
     * 3：事件
     * 4：确认
     * 5：反确认
     * 9：变更
     */
    public static final OID iMAPNorthboundAlarmCategory = new OID(prefixOID, 2);

    /**
     * 告警发生时间。
     * 支持两种格式：
     * 1：yyyy-mm-dd hh:MM:ss %TZ [%DST]
     * 2：yyyy-mm-dd hh:MM:ss
     */
    public static final OID iMAPNorthboundAlarmOccurTime = new OID(prefixOID, 3);

    /**
     * 设备名称
     */
    public static final OID iMAPNorthboundAlarmMOName = new OID(prefixOID, 4);

    /**
     * 产品系列标识
     *
     * 6：网管自身的告警
     * 5：设备上报告警
     */
    public static final OID iMAPNorthboundAlarmProductID = new OID(prefixOID, 5);

    /**
     * 设备类型
     */
    public static final OID iMAPNorthboundAlarmNEType = new OID(prefixOID, 6);

    /**
     * 设备唯一标识
     */
    public static final OID iMAPNorthboundAlarmNEDevID = new OID(prefixOID, 7);

    /**
     * 告警的设备流水号，由设备分配，同一种网元内部唯一例如：“550142”
     */
    public static final OID iMAPNorthboundAlarmDevCsn = new OID(prefixOID, 8);

    /**
     * 告警ID（告警码），用来区分同一种类型设备的告警类型
     * 例如：1100138
     */
    public static final OID iMAPNorthboundAlarmID = new OID(prefixOID, 9);

    /**
     * 告警类型
     * 默认使用eSight规格，取值范围如下：
     * 1：电源系统
     * 2：环境系统
     * 3：信令系统
     * 4：中继系统
     * 5：硬件系统
     * 6：软件系统
     * 7：运行系统
     * 8：通讯系统
     * 9：业务质量
     * 10：处理出错
     * 11：网管内部
     * 12：完整性违背
     * 13：操作违背
     * 14：物理违背
     * 15：安全服务或机制违背
     * 16：时间域违背
     */
    public static final OID iMAPNorthboundAlarmType = new OID(prefixOID, 10);

    /**
     *
     * 告警级别，取值范围如下：
     * 1：紧急
     * 2：重要
     * 3：次要
     * 4：提示
     * 5：不明确
     * 6：恢复
     */
    public static final OID iMAPNorthboundAlarmLevel = new OID(prefixOID, 11);

    /**
     * 告警恢复标志，取值范围如下：
     * 1：已恢复
     * 2：未恢复
     */
    public static final OID iMAPNorthboundAlarmRestore = new OID(prefixOID, 12);

    /**
     * 告警确认标志，取值范围如下：
     * 1：已确认
     * 2：未确认
     */
    public static final OID iMAPNorthboundAlarmConfirm = new OID(prefixOID, 13);

    /**
     * 告警确认时间，未确认时为空(长度为0的字符串)
     * 支持两种格式：
     * 1：yyyy-mm-dd hh:MM:ss %TZ [%DST]
     * 2：yyyy-mm-dd hh:MM:ss
     */
    public static final OID iMAPNorthboundAlarmAckTime = new OID(prefixOID, 14);

    /**
     * 告警恢复时间
     */
    public static final OID iMAPNorthboundAlarmRestoreTime = new OID(prefixOID, 15);

    /**
     * 进行确认操作的操作员
     */
    public static final OID iMAPNorthboundAlarmOperator = new OID(prefixOID, 16);

    /**
     * 告警分组ID
     */
    public static final OID IMAPNorthboundAlarmParas1 = new OID(prefixOID, 17);


    /**
     * 告警定位信息
     *
     * 例如：“Address=10.137.63.227, Protocol=SNMP, Port=161”
     */
    public static final OID iMAPNorthboundAlarmExtendInfo = new OID(prefixOID, 27);

    /**
     * 告警发生原因，对应客户端界面的告警名称。
     * 例如：“Registration failure of the trap IP address with the device”
     */
    public static final OID iMAPNorthboundAlarmProbablecause = new OID(prefixOID, 28);

    /**
     * 告警修复建议
     * 例如：“Check the SNMP parameters of the device.”
     */
    public static final OID iMAPNorthboundAlarmProposedrepairactions = new OID(prefixOID, 29);

    /**
     * 告警详细原因
     * 例如：“
     * Possible causes:
     * The number of trap IP addresses registered on the device reached the upper limit.
     * ”
     */
    public static final OID iMAPNorthboundAlarmSpecificproblems = new OID(prefixOID, 30);

    /**
     * 告警网元IP地址。
     */
    public static final OID IMAPNorthboundAlarmExtendProductItem1 = new OID(prefixOID, 31);

    /**
     * 扩展字段。上报告警的MODN值。
     * 例如：“NE=34603236”
     */
    public static final OID IMAPNorthboundAlarmExtendProductItem5 = new OID(prefixOID, 35);

    /**
     * 扩展字段。上报告警的网元名称。
     * 例如：“MyDevice 10.137.63.119”
     */
    public static final OID IMAPNorthboundAlarmExtendProductItem6 = new OID(prefixOID, 36);

    /**
     * 清除告警的操作员
     */
    public static final OID iMAPNorthboundAlarmClearOperator = new OID(prefixOID, 46);

    /**
     * 告警对象实例类型，如果告警为设备内部部件告警，该字段为部件的资源类型，比如 Interface
     * 例如：“RH2288H V3”
     */
    public static final OID iMAPNorthboundAlarmObjectInstanceType = new OID(prefixOID, 47);

    /**
     * 告警清除类别。
     * 默认使用eSight规格，为数字类型，取值范围如下：
     *
     * 1：可自动清除的告警
     * 2：不能自动清除的告警
     */
    public static final OID iMAPNorthboundAlarmClearCategory = new OID(prefixOID, 48);

    /**
     *  STRING
     *
     * 告警清除类型
     *
     * 0：告警未被清除
     * 1：正常清除
     * 2：复位清除
     * 3：手动清除
     * 4：配置清除
     * 5：相关性清除
     */
    public static final OID iMAPNorthboundAlarmClearType = new OID(prefixOID, 49);

    /**
     * 影响服务的标记。
     *
     * 1：影响
     * 2：不影响
     * 3：未知
     * 说明：
     * 对于事件告警，该字段上报为0
     */
    public static final OID iMAPNorthboundAlarmServiceAffectFlag = new OID(prefixOID, 50);

    /**
     * 附加信息
     * 例如：“Recommended actions:Contact your service provider to clear the alarm.Failed to register a trap IP address with the device. The target IP address is (10.137.67.83) and the target port is (162).”
     */
    public static final OID iMAPNorthboundAlarmAdditionalInfo = new OID(prefixOID, 51);




}
