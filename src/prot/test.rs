// use cure_asn1::rpki::ObjectType;

// use crate::{cure_repo::FuzzingPP, new_rpki::testing::{base_repo, construct_full}, publication_point::repository_util::RepoConfig, testing::test_util::construct_base_repository};

// pub fn testing(){
//     let mut conf = RepoConfig::default();
//     conf.ca_name = "ta".to_string();
//     let repo = construct_full(&conf, &ObjectType::ROA, 2, 2);
//     let files = repo.create_snap_notification_proto(&conf);
//     println!("{}", files[1].0);
// }