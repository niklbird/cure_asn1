pub fn parse_ip(ip: &Vec<u8>, fam: u8, padding_amount: usize) -> String {
    let mut ret = "".to_string();
    if fam == 1 {
        for i in 0..ip.len() {
            ret += &ip[i].to_string();
            ret += ".";
        }
        for _ in ip.len()..4 {
            ret += "0";
            ret += ".";
        }

        ret = ret[..ret.len() - 1].to_string();

        let tmp = ip.last().unwrap();
        let mut v = 1;

        while tmp & v == 0 && tmp != &0 {
            v = v << 1;
        }

        ret += &format!("/{}", 8 * ip.len() - padding_amount);
    } else if fam == 2 {
        // In two steps
        for i in (0..ip.len()).step_by(2) {
            let mut tmp;
            if i + 1 < ip.len() {
                tmp = format!("{:02x}{:02x}", ip[i], ip[i + 1]);
            } else {
                tmp = format!("{:02x}00", ip[i]);
            }
            tmp = tmp.trim_start_matches('0').to_string();

            if tmp == "" {
                tmp += "0";
            }
            tmp += ":";
            ret += &tmp;
        }
        ret = ret[..ret.len() - 1].to_string();
        let v = ip.len() as f64 / 2.0;
        let v = v.ceil() as usize;
        for _ in v..8 {
            ret += ":0";
        }

        let mut largest = (0, 0, 0);
        let mut currently_in_streak = false;
        let mut current_count = (0, 0, 0);
        let mut ind = 0;
        for val in ret.split(":") {
            if val == "0" {
                current_count.0 += 1;
                if !currently_in_streak {
                    current_count = (current_count.0, ind, ind + 1);
                    currently_in_streak = true;
                } else {
                    current_count.2 += 1;
                }
                if current_count.0 > largest.0 {
                    largest = current_count;
                }
            } else {
                current_count = (0, 0, 0);
                currently_in_streak = false;
            }
            ind += 1;
        }

        if largest.0 > 1 {
            let mut ind = 0;
            let mut new_ret = "".to_string();
            for val in ret.split(":") {
                if ind == largest.1 {
                    new_ret += "::";
                    if new_ret.ends_with(":::") {
                        new_ret = new_ret[..new_ret.len() - 1].to_string();
                    }
                } else if ind < largest.1 || ind >= largest.2 {
                    new_ret += val;
                    new_ret += ":";
                }
                ind += 1;
                // else{
                //     new_ret += val;
                //     new_ret += ":";
                //     ind += 1;
                // }
            }
            if new_ret.ends_with(":") && !new_ret.ends_with("::") {
                new_ret = new_ret[..new_ret.len() - 1].to_string();
            }
            if new_ret == "::0:0:0" {
                println!("{}", ret);
            }
            ret = new_ret;
        }

        ret += &format!("/{}", 8 * ip.len() - padding_amount);
    }

    return ret;
}

pub fn byt_to_in(inp: Vec<u8>) -> u64 {
    let mut result: u64 = 0;
    for byte in inp {
        result = (result << 8) | (byte as u64);
    }
    result
}
