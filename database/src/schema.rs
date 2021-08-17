// @generated automatically by Diesel CLI.

table! {
    clients (id) {
        id -> Text,
        description -> Nullable<Text>,
        associated_with -> Nullable<Text>,
        date_created -> Timestamp,
        creator_id -> Text,
        disabled -> Bool,
    }
}

table! {
    users (name) {
        name -> Text,
        password -> Text,
        disabled -> Nullable<Bool>,
    }
}

joinable!(clients -> users (creator_id));

allow_tables_to_appear_in_same_query!(clients, users,);
